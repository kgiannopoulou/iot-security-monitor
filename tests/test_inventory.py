"""Week 2: device inventory, the persistent asset register, and inventory events."""

import json
import sqlite3

import pytest
from test_detections import engine, run, tcp, udp

from iotmon.assets import AssetRegister
from iotmon.cli import main
from iotmon.config import load_config
from iotmon.models import PacketRecord
from iotmon.pipeline import Monitor
from iotmon.storage import Storage

SENSOR = "24:0a:c4:00:00:20"
ROGUE = "b8:27:eb:00:00:66"


def arp_reply(ts, ip, mac):
    return PacketRecord(ts=ts, protocol="ARP", length=42, src_mac=mac, dst_mac="ff:ff:ff:ff:ff:ff",
                        src_ip=ip, dst_ip=ip, app="ARP", info=f"{ip} is-at {mac}", meta={"arp_op": "reply"})


def mac_tcp(ts, src, dst, sport, dport, flags, src_mac, dst_mac=None):
    rec = tcp(ts, src, dst, sport, dport, flags)
    rec.src_mac, rec.dst_mac = src_mac, dst_mac
    return rec


# -- inventory ------------------------------------------------------------- #
def test_inventory_record_has_week2_fields():
    mon = Monitor(load_config())
    for i in range(3):  # three MQTT sessions from the sensor, each a new flow
        mon.process(mac_tcp(i, "192.168.1.20", "192.168.1.10", 40000 + i, 1883, "S", SENSOR))
        mon.process(mac_tcp(i + 0.1, "192.168.1.10", "192.168.1.20", 1883, 40000 + i, "SA", "dc:a6:32:00:00:10"))
    mon.process(udp(5, "192.168.1.20", "192.168.1.1", 40100, 53, mac=SENSOR))
    sensor = mon.inventory.devices[SENSOR].as_dict()
    assert sensor["ips"] == ["192.168.1.20"]
    assert sensor["connections"] == 4  # 3 TCP + 1 UDP conversation
    assert sensor["first_seen"] == 0 and sensor["last_seen"] == 5
    assert mon.inventory.devices["dc:a6:32:00:00:10"].connections == 3
    assert mon.inventory.devices["dc:a6:32:00:00:10"].services == {1883}


# -- device_change --------------------------------------------------------- #
def test_ip_conflict_is_arp_spoofing():
    eng, inv = engine()
    recs = [arp_reply(0, "192.168.1.1", "50:c7:bf:00:00:01"),
            arp_reply(10, "192.168.1.1", ROGUE),               # rogue claims the gateway IP
            arp_reply(11, "192.168.1.1", ROGUE)]
    alerts = run(eng, inv, recs, "device_change")
    assert len(alerts) == 1
    assert alerts[0].severity == "high" and "T1557.002" in alerts[0].mitre
    assert alerts[0].details["previous_mac"] == "50:c7:bf:00:00:01"


def test_ip_change_within_capture():
    eng, inv = engine()
    recs = [udp(0, "192.168.1.20", "192.168.1.1", 123, 123, mac=SENSOR),
            udp(60, "192.168.1.31", "192.168.1.1", 123, 123, mac=SENSOR)]
    alerts = run(eng, inv, recs, "device_change")
    assert len(alerts) == 1 and alerts[0].severity == "low"
    assert alerts[0].details["previous_ips"] == ["192.168.1.20"]


def test_stable_devices_raise_no_change_events():
    eng, inv = engine()
    recs = [udp(s, "192.168.1.20", "192.168.1.1", 123, 123, mac=SENSOR) for s in range(50)]
    recs += [arp_reply(s, "192.168.1.1", "50:c7:bf:00:00:01") for s in range(50)]
    assert not run(eng, inv, recs, "device_change")


# -- asset register -------------------------------------------------------- #
def _register_with_sensor(path, status="approved"):
    reg = AssetRegister(path)
    mon = Monitor(load_config(), assets=reg, new_asset_status=status)
    mon.process(udp(0, "192.168.1.20", "192.168.1.1", 123, 123, mac=SENSOR))
    mon.close()
    return AssetRegister(path)


def test_register_round_trip(tmp_path):
    reg = _register_with_sensor(tmp_path / "inv.json")
    asset = reg.get(SENSOR)
    assert asset["ip"] == "192.168.1.20" and asset["status"] == "approved"
    assert asset["vendor"].startswith("Espressif")
    assert reg.by_ip()["192.168.1.20"]["key"] == SENSOR
    assert reg.find("192.168.1.20") == SENSOR


def test_register_makes_new_device_immediate(tmp_path):
    """With a register there is no learning period: unknown devices alert at once,
    known ones never do."""
    reg = _register_with_sensor(tmp_path / "inv.json")
    mon = Monitor(load_config(), assets=reg)
    mon.process(udp(1000, "192.168.1.20", "192.168.1.1", 123, 123, mac=SENSOR))
    mon.process(udp(1001, "192.168.1.66", "192.168.1.1", 123, 123, mac=ROGUE))
    mon.close()
    assert [a.src for a in mon.alerts if a.rule == "new_device"] == ["192.168.1.66"]
    assert AssetRegister(tmp_path / "inv.json").get(ROGUE)["status"] == "pending"


def test_register_ip_change(tmp_path):
    reg = _register_with_sensor(tmp_path / "inv.json")
    mon = Monitor(load_config(), assets=reg)
    mon.process(udp(1000, "192.168.1.31", "192.168.1.1", 123, 123, mac=SENSOR))
    mon.close()
    (alert,) = [a for a in mon.alerts if a.rule == "device_change"]
    assert alert.details["compared_with"] == "asset register"
    assert AssetRegister(tmp_path / "inv.json").get(SENSOR)["ip"] == "192.168.1.31"


def test_counters_accumulate_but_replays_do_not_double(tmp_path):
    path = tmp_path / "inv.json"
    _register_with_sensor(path)
    _register_with_sensor(path)  # same traffic again
    assert AssetRegister(path).get(SENSOR)["connections"] == 1
    reg = AssetRegister(path)
    mon = Monitor(load_config(), assets=reg)
    mon.process(udp(500, "192.168.1.20", "192.168.1.1", 124, 123, mac=SENSOR))  # later, new traffic
    mon.close()
    assert AssetRegister(path).get(SENSOR)["connections"] == 2


def test_storage_upgrades_old_database(tmp_path):
    db = sqlite3.connect(tmp_path / "old.db")
    db.execute("CREATE TABLE devices (key TEXT PRIMARY KEY, mac TEXT, ips TEXT, vendor TEXT, name TEXT,"
               " role TEXT, first_seen REAL, last_seen REAL, packets_sent INTEGER, packets_recv INTEGER,"
               " bytes_sent INTEGER, bytes_recv INTEGER, protocols TEXT, services TEXT, peers INTEGER)")
    db.close()
    mon = Monitor(load_config(), Storage(tmp_path / "old.db"))
    mon.process(udp(0, "192.168.1.20", "192.168.1.1", 123, 123, mac=SENSOR))
    mon.close()
    row = sqlite3.connect(tmp_path / "old.db").execute("SELECT connections, status FROM devices").fetchone()
    assert row == (1, "")


# -- the Week 2 workflow on the sample capture ----------------------------- #
@pytest.fixture()
def sample_pcap(tmp_path):
    from scapy.utils import wrpcap

    from generate_sample_pcap import build
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), build())
    return path


def test_learn_then_detect_then_approve(tmp_path, sample_pcap, capsys):
    inv = str(tmp_path / "inv.json")
    # Learn from the first 290 s: the baseline, which ends when the attack starts.
    assert main(["inventory", "learn", str(sample_pcap), "--duration", "290", "--inventory", inv]) == 0
    assert len(AssetRegister(inv)) == 6  # the rogue Pi joins later

    db = str(tmp_path / "run.db")
    main(["read", str(sample_pcap), "-q", "--db", db, "--inventory", inv])
    first = capsys.readouterr().out
    assert "New IoT device detected: 192.168.1.66" in first and "MAC:           b8:27:eb:00:00:66" in first
    assert AssetRegister(inv).get(ROGUE)["status"] == "pending"

    main(["read", str(sample_pcap), "-q", "--db", db, "--inventory", inv])
    assert "new_device" not in capsys.readouterr().out  # already in the register

    assert main(["inventory", "approve", "--all", "--inventory", inv]) == 0
    assert all(a["status"] == "approved" for a in AssetRegister(inv).assets.values())
    capsys.readouterr()
    assert main(["inventory", "show", "--json", "--inventory", inv]) == 0
    view = json.loads(capsys.readouterr().out)
    assert set(view["192.168.1.20"]) >= {"mac", "first_seen", "last_seen", "protocols", "connections"}
    assert view["192.168.1.20"]["protocols"] == ["ARP", "MQTT", "NTP"]


def test_repeated_saves_during_a_live_run_do_not_inflate(tmp_path):
    path = tmp_path / "inv.json"
    _register_with_sensor(path)  # 1 connection recorded earlier
    mon = Monitor(load_config(), assets=AssetRegister(path))
    for i in range(3):  # a later run, saved after every new conversation
        mon.process(udp(500 + i, "192.168.1.20", "192.168.1.1", 200 + i, 123, mac=SENSOR))
        mon.save_assets()
    mon.close()
    assert AssetRegister(path).get(SENSOR)["connections"] == 4


def test_empty_register_is_bootstrapped_from_learning_period(tmp_path):
    """First run with no register: no alert storm. The learning-period devices
    are approved; later arrivals alert and wait for review."""
    path = tmp_path / "inv.json"
    mon = Monitor(load_config(), assets=AssetRegister(path))
    mon.process(udp(0, "192.168.1.20", "192.168.1.1", 123, 123, mac=SENSOR))
    mon.process(udp(120, "192.168.1.66", "192.168.1.1", 123, 123, mac=ROGUE))
    mon.close()
    assert [a.src for a in mon.alerts if a.rule == "new_device"] == ["192.168.1.66"]
    reg = AssetRegister(path)
    assert (reg.get(SENSOR)["status"], reg.get(ROGUE)["status"]) == ("approved", "pending")
