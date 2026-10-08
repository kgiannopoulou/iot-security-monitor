"""Week 6: config.yaml and rules/detection_rules.yaml.

The rule file is documentation that recruiters and analysts read, so it
must not drift from the code: every severity and ATT&CK technique the
engine raises on the sample capture and the scenarios has to be declared
for that rule in the file."""

import re
from pathlib import Path

import pytest
import yaml

from iotmon.capture import read_pcap
from iotmon.cli import main
from iotmon.config import DEFAULT_RULES, load_config, load_rules
from iotmon.detections import DETECTORS
from iotmon.models import RULES, register_rules
from iotmon.pipeline import Monitor

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = [ROOT / "samples" / "iot-lab.pcap", *sorted((ROOT / "samples" / "scenarios").glob("*.pcap"))]
TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")


@pytest.fixture(scope="module")
def alerts():
    out = []
    for pcap in CAPTURES:
        mon = Monitor(load_config())
        mon.run(read_pcap(str(pcap)))
        out += mon.alerts
    return out


def test_every_detector_has_exactly_one_rule():
    rules = load_rules()
    assert sorted(r["detector"] for r in rules) == sorted(DETECTORS)
    assert [r["id"] for r in rules] == [f"DET-{i:03d}" for i in range(1, 10)]


def test_alerts_match_the_rule_file(alerts):
    rules = {r["detector"]: r for r in load_rules()}
    fired = set()
    for a in alerts:
        rule = rules[a.rule]
        fired.add(a.rule)
        assert a.rule_id == rule["id"]
        assert a.severity in rule["severities"], (a.rule, a.severity)
        declared = {t for entry in rule["attack"] for t in TECHNIQUE.findall(entry)}
        assert set(TECHNIQUE.findall(a.mitre)) <= declared, (a.rule, a.mitre)
    assert len(fired) >= 8  # every rule except DET-008, which has its own live and unit tests


def test_settings_reach_the_detectors():
    cfg = load_config()
    assert cfg["detections"]["port_scan"] == {"enabled": True, "window_s": 60, "vertical_threshold": 15,
                                              "horizontal_threshold": 8, "arp_threshold": 12, "cooldown_s": 300}
    assert cfg["detections"]["suspicious_port"]["ports"][6667] == "critical"
    assert cfg["network"]["lab_networks"] == ["192.168.1.0/24", "172.28.0.0/24"]


def test_site_config_overrides_only_its_keys(tmp_path):
    site = tmp_path / "site.yaml"
    site.write_text("network:\n  lab_networks: ['10.9.0.0/24']\n"
                    "detections:\n  port_scan:\n    vertical_threshold: 30\n  traffic_spike:\n    enabled: false\n")
    cfg = load_config(site)
    assert cfg["network"]["lab_networks"] == ["10.9.0.0/24"]
    assert cfg["network"]["internal_networks"]  # untouched
    assert cfg["detections"]["port_scan"]["vertical_threshold"] == 30
    assert cfg["detections"]["port_scan"]["window_s"] == 60
    mon = Monitor(cfg)
    assert "traffic_spike" not in {d.name for d in mon.engine.detectors}


def test_lab_config_and_legacy_toml(tmp_path):
    cfg = load_config(ROOT / "lab" / "monitor.yaml")
    assert cfg["detections"]["new_device"]["known_devices"] == ["172.28.0.1"]
    legacy = tmp_path / "old.toml"
    legacy.write_text('[detections.port_scan]\nvertical_threshold = 25\n')
    assert load_config(legacy)["detections"]["port_scan"]["vertical_threshold"] == 25


def test_custom_rule_file(tmp_path, capsys):
    data = yaml.safe_load(DEFAULT_RULES.read_text(encoding="utf-8"))
    data["rules"][1]["name"] = "Recon"
    data["rules"][1]["settings"]["vertical_threshold"] = 5
    custom = tmp_path / "rules.yaml"
    custom.write_text(yaml.safe_dump(data))
    try:
        assert main(["rules", "--rules", str(custom), "-v"]) == 0
        out = capsys.readouterr().out
        assert "DET-002  port_scan" in out and "Recon" in out and "vertical_threshold = 5" in out
        assert RULES["port_scan"] == ("DET-002", "Recon")
    finally:
        register_rules(load_rules())


def test_invalid_rule_files_are_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: DET-001\n    detector: new_device\n")
    with pytest.raises(ValueError, match="missing"):
        load_rules(bad)
    dup = tmp_path / "dup.yaml"
    rule = {"detector": "new_device", "name": "x", "severities": ["low"], "attack": []}
    dup.write_text(yaml.safe_dump({"rules": [{"id": "DET-001", **rule}, {"id": "DET-001", **rule,
                                                                       "detector": "port_scan"}]}))
    with pytest.raises(ValueError, match="duplicate"):
        load_rules(dup)
