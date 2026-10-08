"""Week 7: industrial (OT) awareness — Modbus/TCP decoding, OT zones and the
communication policy, and the six OT detectors run on samples/ot-lab.pcap."""

import struct
from pathlib import Path

import pytest
from scapy.layers.l2 import Ether

from generate_ot_pcap import PLC, build
from iotmon.capture import read_pcap
from iotmon.config import load_config
from iotmon.modbus import ModbusTracker, parse_modbus
from iotmon.models import PacketRecord
from iotmon.parser import parse_packet
from iotmon.pipeline import Monitor
from iotmon.policy import ZonePolicy

OT_SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "ot-lab.pcap"
OT_RULES = {"DET-010", "DET-011", "DET-012", "DET-013", "DET-014", "DET-015"}
ATTACK_START = 300  # the OT sample's baseline is the first 300 s


# -- Modbus decoding --------------------------------------------------------- #
def _adu(txid, unit, pdu):
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit) + pdu


def test_parse_modbus_requests_and_responses():
    read = parse_modbus(_adu(1, 1, struct.pack(">BHH", 3, 100, 8)), to_server=True)
    assert read == [{"unit": 1, "func": 3, "name": "Read Holding Registers", "write": False,
                     "exception": False, "request": True, "address": 100, "quantity": 8}]
    write = parse_modbus(_adu(2, 1, struct.pack(">BHH", 6, 40, 1500)), to_server=True)[0]
    assert write["name"] == "Write Single Register" and write["write"] and write["address"] == 40
    wmulti = parse_modbus(_adu(3, 1, struct.pack(">BHH", 16, 0, 10) + b"\x14" + bytes(20)), to_server=True)[0]
    assert wmulti["func"] == 16 and wmulti["write"] and wmulti["quantity"] == 10
    # a response carries no address/quantity, and is not a write
    resp = parse_modbus(_adu(2, 1, struct.pack(">BB", 3, 4) + bytes(4)), to_server=False)[0]
    assert resp["request"] is False and resp["write"] is False and "address" not in resp


def test_parse_modbus_exception_and_pipelining():
    exc = parse_modbus(_adu(1, 1, bytes([0x83, 0x02])), to_server=False)[0]
    assert exc["exception"] and exc["func"] == 3 and exc["write"] is False and exc["exception_code"] == 2
    two = _adu(1, 1, struct.pack(">BHH", 3, 0, 1)) + _adu(2, 1, struct.pack(">BHH", 3, 5, 1))
    assert len(parse_modbus(two, to_server=True)) == 2
    assert parse_modbus(b"\x00\x01\x00\x05", to_server=True) == []  # too short, no crash


def test_modbus_tracker_builds_conversation():
    tr = ModbusTracker()

    def rec(payload, to_server):
        sp, dp = (40000, 502) if to_server else (502, 40000)
        src, dst = ("10.0.0.5", "10.0.0.9") if to_server else ("10.0.0.9", "10.0.0.5")
        return PacketRecord(ts=1.0, protocol="TCP", length=60, src_ip=src, dst_ip=dst, sport=sp, dport=dp,
                            app="MODBUS", meta={"modbus": parse_modbus(payload, to_server)})

    evs = tr.update(rec(_adu(1, 1, struct.pack(">BHH", 3, 0, 10)), True))
    assert evs[0].kind == "request" and evs[0].first_request and evs[0].name == "Read Holding Registers"
    tr.update(rec(_adu(2, 1, struct.pack(">BHH", 6, 40, 99)), True))  # a write
    tr.update(rec(_adu(1, 1, struct.pack(">BB", 3, 20) + bytes(20)), False))  # a response
    conv = tr.conversations[("10.0.0.5", "10.0.0.9")]
    assert conv.requests == 2 and conv.writes == 1 and conv.responses == 1
    assert conv.read_registers and conv.write_registers == {40}
    assert "10.0.0.9" in tr.servers


# -- zones and policy -------------------------------------------------------- #
@pytest.fixture
def policy():
    return ZonePolicy(load_config()["ot"])


def test_zone_and_role(policy):
    assert policy.is_ot("192.168.10.20") and policy.zone_of("192.168.1.50") == "IT"
    assert policy.zone_of("8.8.8.8") is None
    assert policy.role_of("192.168.10.20") == "plc"
    assert policy.role_of("192.168.10.99", plc_ips={"192.168.10.99"}) == "plc"  # inferred from Modbus
    assert policy.role_of("192.168.1.50") == "it"


def test_policy_allows_and_denies(policy):
    plc, ews, hmi = "192.168.10.20", "192.168.10.10", "192.168.10.11"
    office, rogue_ot = "192.168.1.50", "192.168.10.66"
    assert policy.allowed(ews, plc) and policy.allowed(hmi, plc)
    assert not policy.allowed(office, plc)          # IT -> OT: segmentation violation
    assert policy.allowed(rogue_ot, plc)            # intra-OT passes zone check (Modbus allowlist catches it)
    assert policy.allowed(office, "8.8.8.8")        # dst not OT: not this policy's concern
    assert policy.modbus_client_allowed(ews) and not policy.modbus_client_allowed(office)
    assert policy.modbus_writer_allowed(ews) and not policy.modbus_writer_allowed(hmi)


def test_disabled_without_config():
    pol = ZonePolicy()
    assert not pol.enabled and pol.zone_of("192.168.10.20") is None
    assert pol.allowed("1.2.3.4", "192.168.10.20")  # nothing is OT, so nothing is denied


# -- end to end on the OT sample capture ------------------------------------- #
def _wire(pkt):
    out = Ether(bytes(pkt))
    out.time = pkt.time
    return out


@pytest.fixture(scope="module")
def records():
    return [parse_packet(_wire(p)) for p in build()]


def _run(records):
    mon = Monitor(load_config())
    for r in records:
        mon.process(r)
    mon.close()
    return mon


@pytest.fixture(scope="module")
def monitor(records):
    return _run(records)


def test_ot_baseline_is_quiet(records):
    """The first 300 s of normal Modbus polling raise no alerts."""
    mon = Monitor(load_config())
    base = records[0].ts + ATTACK_START
    for r in records:
        if r.ts >= base:
            break
        mon.process(r)
    mon.close()
    assert mon.alerts == []


def test_all_ot_rules_fire(monitor):
    fired = {a.rule_id for a in monitor.alerts}
    assert OT_RULES <= fired, OT_RULES - fired


def test_ot_attack_timeline(monitor):
    ot = [(a.rule_id, a.severity, a.title) for a in monitor.alerts if a.rule_id in OT_RULES]
    expected = [
        ("DET-012", "high", "Segmentation violation: IT host 192.168.1.50 connected to OT device 192.168.10.20"),
        ("DET-011", "high", "Unauthorized Modbus client: 192.168.1.50 read from PLC 192.168.10.20"),
        ("DET-011", "critical", "Unauthorized Modbus client: 192.168.1.50 wrote to PLC 192.168.10.20"),
        ("DET-010", "high", "New OT asset detected: 192.168.10.66"),
        ("DET-011", "high", "Unauthorized Modbus client: 192.168.10.66 read from PLC 192.168.10.20"),
        ("DET-014", "medium", "Abnormal Modbus request rate: 192.168.1.50"),
        ("DET-013", "high", "Unexpected protocol in OT zone: TELNET involving 192.168.10.20"),
        ("DET-015", "critical", "OT device communicating externally: plc 192.168.10.20"),
    ]
    assert len(ot) == len(expected), ot
    for (rule, sev, title), (wr, ws, prefix) in zip(ot, expected):
        assert (rule, sev) == (wr, ws) and title.startswith(prefix), (rule, sev, title)


def test_unauthorized_write_is_critical(monitor):
    writes = [a for a in monitor.alerts if a.rule_id == "DET-011" and a.details.get("write")]
    assert writes and all(a.severity == "critical" for a in writes)
    assert writes[0].details["function"] == "Write Single Register"


def test_ot_asset_records(monitor):
    devs = {next(iter(d.ips)): d for d in monitor.inventory.devices.values()}
    plc = devs["192.168.10.20"]
    assert plc.zone == "OT" and plc.device_type == "PLC" and plc.risk_score >= 80
    assert devs["192.168.10.10"].device_type == "EWS"
    assert devs["192.168.1.50"].zone == "IT"
    # the PLC is the highest-risk asset on the network
    assert max(devs.values(), key=lambda d: d.risk_score).device_type == "PLC"


def test_modbus_conversations_recorded(monitor):
    convs = monitor.engine.ctx.modbus.conversations
    assert ("192.168.10.10", "192.168.10.20") in convs       # EWS -> PLC
    ews = convs[("192.168.10.10", "192.168.10.20")]
    assert ews.writes > 0 and "Read Holding Registers" in ews.functions
    assert "192.168.10.20" in monitor.engine.ctx.modbus.servers


def test_dashboard_exposes_modbus_and_zones(tmp_path, records):
    from iotmon.dashboard.app import create_app
    from iotmon.storage import Storage

    db = tmp_path / "ot.db"
    mon = Monitor(load_config(), Storage(db, reset=True, mode="read", source="ot"))
    for r in records:
        mon.process(r)
    mon.close()
    client = create_app(db).test_client()
    mb = client.get("/api/modbus").get_json()
    assert mb["servers"] == ["192.168.10.20"]
    ews = next(c for c in mb["conversations"] if c["client"] == "192.168.10.10")
    assert ews["writes"] > 0 and "Read Holding Registers" in ews["functions"]
    devices = {d["ips"]: d for d in client.get("/api/devices").get_json()}
    assert devices["192.168.10.20"]["zone"] == "OT" and devices["192.168.10.20"]["device_type"] == "PLC"
    assert devices["192.168.10.20"]["risk_score"] >= 80
    assert b"Modbus/TCP conversations" in client.get("/").data


def test_committed_ot_sample_matches_generator(records):
    on_disk = list(read_pcap(str(OT_SAMPLE)))
    assert len(on_disk) == len(records)
    assert [r.info for r in on_disk] == [r.info for r in records]
