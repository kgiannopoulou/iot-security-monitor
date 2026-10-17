"""Confidence scoring, custom YAML rules (schema-validated), SIEM output
(ECS, CEF, syslog), structured logs, and the passive-monitoring guarantee."""

import json
import re
import socket
from pathlib import Path

import pytest
import yaml

from iotmon.capture import read_pcap
from iotmon.cli import main
from iotmon.config import load_config
from iotmon.custom_rules import RuleFileError, load as load_custom, validate
from iotmon.models import Alert
from iotmon.pipeline import Monitor
from iotmon.siem import SyslogForwarder, alert_row, to_cef, to_ecs

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "iot-lab.pcap"
EXAMPLE = ROOT / "rules" / "custom_rules.example.yaml"


@pytest.fixture(scope="module")
def sample_alerts():
    mon = Monitor(load_config(custom_rules=EXAMPLE))
    mon.run(read_pcap(str(SAMPLE)))
    return mon.alerts


# -- confidence ---------------------------------------------------------------- #
def test_every_alert_has_a_confidence_with_reasons(sample_alerts):
    for a in sample_alerts:
        assert 0.05 <= a.confidence <= 0.99
        assert a.details["confidence_reasons"][0].startswith("rule prior")
    d = sample_alerts[0].as_dict()
    assert d["confidence_level"] in ("low", "medium", "high")


def test_corroborated_alerts_from_the_rogue_device_score_high(sample_alerts):
    rogue = [a for a in sample_alerts if a.src == "192.168.1.66" and a.rule_id.startswith("DET")]
    later = [a for a in rogue if a.rule_id != "DET-001"]
    assert later and all(a.confidence >= 0.75 for a in later)
    assert any("same source also raised DET-001" in r for a in later for r in a.details["confidence_reasons"])


def test_custom_rule_confidence_starts_from_its_own_prior(sample_alerts):
    irc = next(a for a in sample_alerts if a.rule_id == "CUS-002")
    assert irc.details["confidence_reasons"][0] == "rule prior 0.90"


# -- custom rules ---------------------------------------------------------------- #
def test_example_custom_rules_validate_and_fire_on_the_attack(sample_alerts):
    fired = {a.rule_id for a in sample_alerts if a.rule_id.startswith("CUS")}
    assert fired == {"CUS-001", "CUS-002", "CUS-003"}  # CUS-004 is disabled in the file
    telnet = next(a for a in sample_alerts if a.rule_id == "CUS-001")
    assert (telnet.src, telnet.dst, telnet.severity) == ("192.168.1.66", "192.168.1.22", "high")
    fanout = next(a for a in sample_alerts if a.rule_id == "CUS-003")
    assert fanout.details["count"] == 3 and fanout.details["distinct"] == "dst"


def test_custom_rules_do_not_change_the_built_in_results(sample_alerts):
    builtin = [a for a in sample_alerts if a.rule_id.startswith("DET")]
    assert len(builtin) == 12


def test_schema_reports_every_problem_with_its_path(tmp_path):
    bad = {"custom_rules": [
        {"id": "CUS-1", "name": "x", "severity": "severe", "match": {"dst_prot": 23}},
        {"id": "CUS-002", "name": "Okay name", "severity": "low", "match": {"src_net": "10.0.0.300/8"}},
        {"id": "CUS-002", "name": "Duplicate", "severity": "low", "match": {"protocol": "TCP"},
         "threshold": {"count": 1, "window_s": 0}},
    ]}
    with pytest.raises(RuleFileError) as err:
        validate(bad, "bad.yaml")
    text = "\n".join(err.value.errors)
    for expected in ("custom_rules[0].id", "custom_rules[0].severity", "custom_rules[0].name",
                     "'dst_prot' was unexpected", "custom_rules[1].match.src_net",
                     "custom_rules[2].id: duplicate", "custom_rules[2].threshold.count",
                     "custom_rules[2].threshold.window_s"):
        assert expected in text, text


def test_rules_validate_command_exit_codes(tmp_path, capsys):
    assert main(["rules", "validate", str(EXAMPLE), str(ROOT / "rules" / "detection_rules.yaml")]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"custom_rules": [{"id": "CUS-001", "name": "No match block", "severity": "low"}]}))
    assert main(["rules", "validate", str(bad)]) == 1
    assert "'match' is a required property" in capsys.readouterr().out


def test_an_invalid_rule_file_stops_the_monitor_before_it_runs(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("custom_rules:\n  - {id: CUS-001, name: Typo rule, severity: high, match: {dst_prot: 23}}\n")
    assert main(["read", str(SAMPLE), "--no-store", "-q", "--custom-rules", str(bad)]) == 2
    assert "dst_prot" in capsys.readouterr().err


def test_threshold_counts_distinct_values_per_group():
    from iotmon.custom_rules import CustomRuleDetector
    from iotmon.detections import Context
    from iotmon.inventory import Inventory
    from iotmon.models import PacketRecord

    det = CustomRuleDetector({"id": "CUS-009", "name": "Port sweep", "severity": "medium",
                              "match": {"protocol": "TCP"},
                              "threshold": {"count": 4, "window_s": 10, "group_by": "src", "distinct": "dst_port"}})
    ctx = Context(Inventory(["192.168.1.0/24"]))
    rec = lambda t, port, src="192.168.1.5": PacketRecord(t, "TCP", 60, src_ip=src, dst_ip="192.168.1.10",  # noqa: E731
                                                         sport=40000, dport=port)
    assert det.on_packet(rec(0, 22), ctx) == [] and det.on_packet(rec(1, 22), ctx) == []  # same port twice
    assert det.on_packet(rec(2, 80), ctx) == [] and det.on_packet(rec(3, 443), ctx) == []
    assert det.on_packet(rec(4, 25, src="192.168.1.6"), ctx) == []  # another source, own group
    alerts = det.on_packet(rec(5, 8080), ctx)
    assert len(alerts) == 1 and alerts[0].details["count"] == 4
    assert det.on_packet(rec(20, 9000), ctx) == []  # window expired, cooldown anyway


def test_site_config_can_point_at_a_custom_rule_file(tmp_path):
    (tmp_path / "my_rules.yaml").write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    site = tmp_path / "site.yaml"
    site.write_text("custom_rules: my_rules.yaml\n")
    cfg = load_config(site)
    assert [r["id"] for r in cfg["custom_rules"]] == ["CUS-001", "CUS-002", "CUS-003", "CUS-004"]
    assert load_custom(EXAMPLE)[3]["enabled"] is False


# -- SIEM output ----------------------------------------------------------------- #
def _alert(**kw):
    base = dict(ts=1791369300.25, rule="port_scan", severity="high", title="Port scan: 30 ports",
                src="192.168.1.66", dst="192.168.1.22", mitre="T1046 Network Service Discovery",
                details={"ports_observed": 30, "port": 23}, confidence=0.9)
    base.update(kw)
    return Alert(**base)


def test_ecs_document_has_the_fields_a_siem_indexes():
    doc = to_ecs(alert_row(_alert(), alert_id=7))
    assert doc["@timestamp"] == "2026-10-07T10:35:00.250Z"
    assert doc["event"]["kind"] == "alert" and "intrusion_detection" in doc["event"]["category"]
    assert doc["event"]["severity"] == 4
    assert doc["rule"] == {"id": "DET-002", "name": "port_scan", "category": "IoT/OT network"}
    assert doc["source"] == {"ip": "192.168.1.66"} and doc["destination"] == {"ip": "192.168.1.22", "port": 23}
    assert doc["threat"]["technique"] == {"id": ["T1046"], "name": ["Network Service Discovery"]}
    assert doc["labels"]["confidence"] == "high" and doc["iotmon"]["alert_id"] == 7


def test_cef_line_escapes_header_and_extension_values():
    line = to_cef(alert_row(_alert(title="a=b | c\\d\nnext", rule="port_scan")))
    assert line.startswith("CEF:0|iotmon|IoT Security Monitor|")
    parts = line.split("|", 7)  # 7 header fields; pipes are legal (unescaped) in the extension
    assert parts[4:7] == ["DET-002", "port_scan", "8"]
    ext = parts[7]
    assert "msg=a\\=b | c\\\\d\\nnext" in ext
    assert "src=192.168.1.66" in ext and "dst=192.168.1.22" in ext and "cfp1=0.9" in ext


def test_syslog_forwarder_sends_rfc5424_with_a_cef_body():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)
    fwd = SyslogForwarder(f"127.0.0.1:{server.getsockname()[1]}", "cef", hostname="sensor-1")
    fwd.alert(_alert())
    data = server.recv(65535).decode()
    fwd.close()
    server.close()
    # PRI = local4 (20) * 8 + syslog severity 3 (error) for "high"
    assert re.match(r"<163>1 2026-10-07T10:35:00\.250Z sensor-1 iotmon - DET-002 - CEF:0\|iotmon\|", data), data


def test_syslog_target_must_be_host_and_port():
    with pytest.raises(ValueError, match="HOST:PORT"):
        SyslogForwarder("siem.example")


def test_export_ecs_and_cef_from_the_database(tmp_path, capsys):
    db = tmp_path / "iotmon.db"
    assert main(["read", str(SAMPLE), "--db", str(db), "-q"]) == 0
    capsys.readouterr()
    assert main(["alerts", "export", "--db", str(db), "--format", "ecs"]) == 0
    docs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(docs) == 12 and all(d["event"]["kind"] == "alert" for d in docs)
    assert all("confidence" in d["iotmon"] for d in docs)
    assert main(["alerts", "export", "--db", str(db), "--format", "cef"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 12 and all(line.startswith("CEF:0|") for line in lines)


# -- structured logs --------------------------------------------------------------- #
def test_json_logs_record_the_run_and_every_alert(tmp_path):
    log = tmp_path / "iotmon.log"
    assert main(["read", str(SAMPLE), "--no-store", "-q", "--log-format", "json", "--log-file", str(log)]) == 0
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert events[0]["event"] == "run started" and events[0]["mode"] == "read" and events[0]["rules"] == 15
    alerts = [e for e in events if e["event"] == "alert"]
    assert len(alerts) == 12 and all(e["level"] == "warning" and e["rule_id"] and e["confidence"] for e in alerts)
    done = events[-1]
    assert done["event"] == "run finished" and done["packets"] == 3546 and done["packets_per_s"] > 0


# -- passive by design --------------------------------------------------------------- #
def test_the_monitor_never_transmits_on_the_monitored_network():
    """No scapy send/sr functions anywhere in the package, and the only
    socket is the opt-in syslog forwarder to a SIEM."""
    send_calls = re.compile(r"\b(sendp?|sr1?|srp1?|srloop|srflood|sendpfast)\s*\(")
    for path in (ROOT / "src" / "iotmon").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not send_calls.search(text), f"{path.name} transmits packets"
        if path.name != "siem.py":
            assert "socket.socket(" not in text, f"{path.name} opens a network socket"


def test_ecs_file_sink_writes_one_document_per_alert(tmp_path):
    out = tmp_path / "alerts.ecs.ndjson"
    assert main(["read", str(SAMPLE), "--no-store", "-q", "--ecs-file", str(out)]) == 0
    docs = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(docs) == 12 and docs[0]["rule"]["id"] == "DET-001"
    assert docs[0]["@timestamp"] < docs[-1]["@timestamp"]
