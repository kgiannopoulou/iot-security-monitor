"""Week 8: the SOC-analyst layer — INFO severity, the risk model, the analyst
alert view, PCAP carving and the security report."""

import json
from pathlib import Path

import pytest

from iotmon.cli import main
from iotmon.config import load_config
from iotmon.models import SEVERITIES, rule_meta
from iotmon.pipeline import Monitor
from iotmon.state import (alert_detail, enrich_risk, render_report, render_report_html, render_report_md,
                          risk_status, security_report, security_state)
from iotmon.storage import Storage

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "iot-lab.pcap"
OT_SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "ot-lab.pcap"


@pytest.fixture(scope="module")
def ot_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("w8") / "iotmon.db"
    assert main(["read", str(OT_SAMPLE), "-q", "--db", str(db)]) == 0
    return db


# -- INFO severity ----------------------------------------------------------- #
def test_info_is_the_lowest_severity():
    assert SEVERITIES[0] == "info"
    assert risk_status(0) == "INFO" and risk_status(19) == "INFO" and risk_status(20) == "LOW"


def test_info_alerts_do_not_raise_the_posture(tmp_path):
    from iotmon.models import Alert, PacketRecord
    db = tmp_path / "i.db"
    mon = Monitor(load_config(), Storage(db, reset=True))
    mon.process(PacketRecord(ts=60, protocol="UDP", length=90, src_ip="192.168.1.20", dst_ip="192.168.1.1",
                             src_mac="24:0a:c4:00:00:20", sport=123, dport=123, app="NTP"))
    mon._emit([Alert(61, "mqtt_activity", "info", "new subscription", src="192.168.1.20")])
    mon.close()
    s = security_state(db)
    assert s["posture"]["level"] == "OK" and s["by_severity"][-1]["severity"] == "info"
    assert s["by_severity"][-1]["count"] == 1


# -- risk model -------------------------------------------------------------- #
def test_enrich_risk_adds_alert_points():
    dev = {"risk_score": 10, "ips": "192.168.10.20"}
    alerts = [{"rule_id": "DET-011", "src": "192.168.10.20", "details": {"write": True}},
              {"rule_id": "DET-002", "src": "192.168.10.20", "details": {}},
              {"rule_id": "DET-015", "src": "192.168.10.20", "details": {}}]
    r = enrich_risk(dev, alerts)
    assert r["base"] == 10
    assert r["score"] == min(100, 10 + 40 + 30 + 40) and r["status"] == "CRITICAL"
    labels = [b["reason"] for b in r["breakdown"]]
    assert "Unauthorized PLC write" in labels and "Scanning activity" in labels


def test_enrich_risk_dedupes_by_category():
    dev = {"risk_score": 0, "ips": "x"}
    two_scans = [{"rule_id": "DET-002", "src": "x", "details": {}},
                 {"rule_id": "DET-002", "src": "x", "details": {}}]
    assert enrich_risk(dev, two_scans)["score"] == 30  # counted once


# -- analyst alert view ------------------------------------------------------ #
def test_alert_detail_card(ot_db):
    # find the critical unauthorized-write alert
    import sqlite3
    con = sqlite3.connect(ot_db)
    aid = con.execute("SELECT id FROM alerts WHERE rule = 'unauthorized_modbus' AND severity = 'critical'"
                      " ORDER BY id LIMIT 1").fetchone()[0]
    con.close()
    d = alert_detail(ot_db, aid)
    assert d["alert_ref"] == f"ALT-{aid:04d}" and d["severity"] == "critical"
    assert d["source"]["ip"] == "192.168.1.50" and d["destination"]["device_type"] == "PLC"
    assert d["destination"]["risk"]["status"] in ("HIGH", "CRITICAL")
    assert d["protocol"] == "Modbus/TCP"
    assert d["response"] and "physical process" in " ".join(d["response"]).lower()
    assert any("T0855" in t for t in d["attack"])
    assert d["pcap"]["available"] and d["pcap"]["capture"].endswith("ot-lab.pcap")


def test_alert_detail_missing(ot_db):
    assert alert_detail(ot_db, 99999) is None


def test_rule_meta_has_response():
    assert rule_meta("DET-011")["response"]
    assert rule_meta("unauthorized_modbus") == rule_meta("DET-011")


# -- PCAP carving ------------------------------------------------------------ #
def test_pcap_carve(ot_db, tmp_path):
    import sqlite3
    from scapy.layers.inet import IP
    from scapy.utils import rdpcap
    con = sqlite3.connect(ot_db)
    aid = con.execute("SELECT id FROM alerts WHERE rule = 'ot_segmentation' LIMIT 1").fetchone()[0]
    con.close()
    out = tmp_path / "a.pcap"
    assert main(["pcap", str(aid), "--db", str(ot_db), "-o", str(out), "-w", "20"]) == 0
    pkts = rdpcap(str(out))
    assert len(pkts) > 0
    hosts = {p[IP].src for p in pkts if IP in p} | {p[IP].dst for p in pkts if IP in p}
    assert {"192.168.1.50", "192.168.10.20"} & hosts  # the alert's endpoints appear


def test_pcap_unavailable_for_live(tmp_path, capsys):
    """An alert with no retained capture cannot be carved."""
    from iotmon.models import Alert, PacketRecord
    db = tmp_path / "live.db"
    mon = Monitor(load_config(), Storage(db, reset=True, mode="live", source="eth0"))
    mon.process(PacketRecord(ts=1, protocol="TCP", length=60, src_ip="192.168.1.5", dst_ip="192.168.1.10",
                             sport=4000, dport=1883, app="MQTT"))
    mon._emit([Alert(2, "port_scan", "high", "scan", src="192.168.1.5")])
    mon.close()
    assert main(["pcap", "1", "--db", str(db)]) == 1
    assert "no retained capture" in capsys.readouterr().err


# -- security report --------------------------------------------------------- #
def test_security_report(ot_db):
    r = security_report(ot_db)
    assert r["assets"]["total"] == 7 and r["assets"]["ot"] >= 4
    assert r["traffic"]["packets"] > 1000
    assert r["alerts"]["by_severity"]["critical"] == 2
    assert r["highest_risk"]["device_type"] == "PLC" and r["highest_risk"]["status"] == "CRITICAL"
    assert r["top_detection"]["rule_id"] == "DET-011"
    text = render_report(r, utc=True)
    assert "IoT/OT SECURITY REPORT" in text and "Highest Risk Asset" in text and "Risk Score: 100/100" in text
    assert "# IoT/OT Security Report" in render_report_md(r)
    assert "<!doctype html>" in render_report_html(r).lower() and "Highest-risk asset" in render_report_html(r)


def test_cli_alert_and_summary(ot_db, capsys, tmp_path):
    db = ["--db", str(ot_db)]
    assert main(["alert", "1", *db, "--json"]) == 0
    card = json.loads(capsys.readouterr().out)
    assert card["alert_ref"] == "ALT-0001" and "source" in card

    assert main(["summary", *db]) == 0
    assert "SECURITY REPORT" in capsys.readouterr().out
    html = tmp_path / "r.html"
    assert main(["summary", *db, "--format", "html", "-o", str(html)]) == 0
    assert "Highest-risk asset" in html.read_text(encoding="utf-8")


# -- dashboard endpoints ----------------------------------------------------- #
def test_dashboard_alert_and_report(ot_db):
    from iotmon.dashboard.app import create_app
    client = create_app(ot_db).test_client()
    d = client.get("/api/alert/1").get_json()
    assert d["alert_ref"] == "ALT-0001" and d["source"]["ip"]
    assert client.get("/api/alert/99999").status_code == 404
    rep = client.get("/api/report").get_json()
    assert rep["highest_risk"]["status"] == "CRITICAL"
    assert b"investigate" in client.get("/").data
