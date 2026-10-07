"""Replay the bundled sample capture through the whole pipeline."""

import json
import sqlite3
from pathlib import Path

import pytest
from scapy.layers.l2 import Ether

from generate_sample_pcap import START, build
from iotmon.capture import read_pcap
from iotmon.config import load_config
from iotmon.parser import parse_packet
from iotmon.pipeline import Monitor
from iotmon.storage import Storage

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "iot-lab.pcap"
ATTACK_START = START + 300


def _wire(pkt):
    """Serialise and re-dissect, as if the packet had been read from a capture."""
    out = Ether(bytes(pkt))
    out.time = pkt.time
    return out


@pytest.fixture(scope="module")
def records():
    return [parse_packet(_wire(p)) for p in build()]


@pytest.fixture(scope="module")
def monitor(records, tmp_path_factory):
    out = tmp_path_factory.mktemp("run")
    mon = Monitor(load_config(), Storage(out / "iotmon.db", packet_csv=True, reset=True))
    for r in records:
        mon.process(r)
    mon.close()
    mon.out = out
    return mon


def test_baseline_is_quiet(records):
    """No false positives during five minutes of normal operation."""
    mon = Monitor(load_config())
    for r in records:
        if r.ts >= ATTACK_START:
            break
        mon.process(r)
    mon.close()
    assert mon.alerts == []


def test_every_attack_stage_is_detected(monitor):
    """The exact incident timeline, one alert per stage (rule ID, title prefix)."""
    expected = [
        ("DET-001", "New IoT device detected: 192.168.1.66"),
        ("DET-002", "ARP sweep from 192.168.1.66"),
        ("DET-002", "Port scan: 192.168.1.66 probed 15 ports on 192.168.1.22"),
        ("DET-004", "TELNET session 192.168.1.66 -> 192.168.1.22:23"),
        ("DET-007", "Repeated failed connections: 192.168.1.66 -> 192.168.1.21:23"),
        ("DET-007", "MQTT authentication failures: 192.168.1.66"),
        ("DET-005", "Unexpected external connection: 192.168.1.22 -> 198.51.100.23:6667 (cnc.badbot.example)"),
        ("DET-004", "IRC session 192.168.1.22 -> 198.51.100.23:6667"),
        ("DET-005", "Unexpected external connection: 192.168.1.22 -> 198.51.100.77"),
        ("DET-003", "Abnormal connection rate: 192.168.1.22"),
        ("DET-006", "Traffic spike: 192.168.1.22 sent"),
    ]
    got = [(a.rule_id, a.title) for a in monitor.alerts]
    assert len(got) == len(expected), got
    for (rule, title), (want_rule, prefix) in zip(got, expected):
        assert rule == want_rule and title.startswith(prefix), (rule, title)


def test_learned_baseline(monitor):
    """What the first two minutes taught the monitor about each device."""
    b = monitor.baseline
    assert b.get("192.168.1.20").client_ports == {123, 1883}
    assert b.get("192.168.1.21").external_peers == {"203.0.113.50"}
    assert b.get("192.168.1.22").server_ports == {80}
    assert b.get("192.168.1.22").external_peers == {"203.0.113.80"}
    assert "192.168.1.66" not in b  # the rogue device arrives after the baseline


def test_inventory(monitor):
    devices = {next(iter(d.ips)): d for d in monitor.inventory.devices.values()}
    assert set(devices) == {"192.168.1.1", "192.168.1.5", "192.168.1.10", "192.168.1.20",
                            "192.168.1.21", "192.168.1.22", "192.168.1.66"}
    assert devices["192.168.1.10"].role == "MQTT broker"
    assert devices["192.168.1.20"].name == "temp-sensor-01"
    assert devices["192.168.1.22"].services == {23, 80}
    assert devices["192.168.1.66"].vendor.startswith("Raspberry Pi")


def test_outputs_written(monitor):
    db = sqlite3.connect(monitor.out / "iotmon.db")
    assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == len(monitor.alerts)
    assert db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 7
    assert db.execute("SELECT SUM(packets) FROM traffic").fetchone()[0] == monitor.packets
    assert db.execute("SELECT COUNT(*) FROM flows WHERE app = 'MQTT'").fetchone()[0] > 0
    db.close()
    lines = (monitor.out / "alerts.jsonl").read_text().splitlines()
    assert len(lines) == len(monitor.alerts)
    first = json.loads(lines[0])
    assert (first["rule"], first["severity"], first["source_ip"]) == ("DET-001", "MEDIUM", "192.168.1.66")
    csv_lines = (monitor.out / "packets.csv").read_text().splitlines()
    assert len(csv_lines) == monitor.packets + 1


def test_committed_sample_matches_generator(records):
    on_disk = list(read_pcap(str(SAMPLE)))
    assert len(on_disk) == len(records)
    assert [r.info for r in on_disk] == [r.info for r in records]
