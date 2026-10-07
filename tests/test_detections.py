"""Each detector in isolation, driven with hand-made records."""

from iotmon.config import load_config
from iotmon.detections import DetectionEngine
from iotmon.inventory import Inventory
from iotmon.models import PacketRecord


def engine(**overrides):
    cfg = load_config()["detections"]
    for name, values in overrides.items():
        cfg[name].update(values)
    inv = Inventory(["192.168.1.0/24"])
    return DetectionEngine(cfg, inv), inv


def run(eng, inv, recs, rule=None):
    alerts = []
    for r in recs:
        alerts += eng.process(r, inv.update(r))
    alerts += eng.flush()
    return [a for a in alerts if rule is None or a.rule == rule]


def tcp(ts, src, dst, sport, dport, flags, length=60, **meta):
    return PacketRecord(ts=ts, protocol="TCP", length=length, src_ip=src, dst_ip=dst,
                        sport=sport, dport=dport, tcp_flags=flags, meta=meta)


def udp(ts, src, dst, sport, dport, length=90, mac=None):
    return PacketRecord(ts=ts, protocol="UDP", length=length, src_ip=src, dst_ip=dst,
                        sport=sport, dport=dport, src_mac=mac)


# -- port scan ------------------------------------------------------------- #
def test_vertical_port_scan():
    eng, inv = engine()
    recs = [tcp(i * 0.1, "192.168.1.66", "192.168.1.22", 40000, 1000 + i, "S") for i in range(20)]
    alerts = run(eng, inv, recs, "port_scan")
    assert len(alerts) == 1 and alerts[0].severity == "high"


def test_slow_scan_outside_window_is_not_flagged():
    eng, inv = engine()
    recs = [tcp(i * 10.0, "192.168.1.66", "192.168.1.22", 40000, 1000 + i, "S") for i in range(20)]
    assert not run(eng, inv, recs, "port_scan")


def test_horizontal_sweep():
    eng, inv = engine()
    recs = [tcp(i * 0.1, "192.168.1.66", f"192.168.1.{100 + i}", 40000, 1883, "S") for i in range(10)]
    assert any("Host sweep" in a.title for a in run(eng, inv, recs, "port_scan"))


def test_arp_sweep():
    eng, inv = engine()
    recs = [PacketRecord(ts=i * 0.05, protocol="ARP", length=42, src_ip="192.168.1.66",
                         dst_ip=f"192.168.1.{i}", src_mac="b8:27:eb:00:00:66", meta={"arp_op": "request"})
            for i in range(1, 20)]
    assert any("ARP sweep" in a.title for a in run(eng, inv, recs, "port_scan"))


def test_dns_server_replies_are_not_a_scan():
    eng, inv = engine()
    recs = [udp(i * 0.1, "192.168.1.1", "192.168.1.21", 53, 50000 + i) for i in range(40)]
    assert not run(eng, inv, recs, "port_scan")


# -- new device ------------------------------------------------------------ #
def test_new_device_only_after_learning_period():
    eng, inv = engine(new_device={"learning_period_s": 60})
    recs = [udp(0, "192.168.1.20", "192.168.1.1", 123, 123, mac="24:0a:c4:00:00:20"),
            udp(120, "192.168.1.66", "192.168.1.1", 123, 123, mac="b8:27:eb:00:00:66")]
    assert [a.src for a in run(eng, inv, recs, "new_device")] == ["192.168.1.66"]


def test_known_device_is_allowlisted():
    eng, inv = engine(new_device={"known_devices": ["B8:27:EB:00:00:66"]})
    recs = [udp(0, "192.168.1.20", "192.168.1.1", 123, 123, mac="24:0a:c4:00:00:20"),
            udp(120, "192.168.1.66", "192.168.1.1", 123, 123, mac="b8:27:eb:00:00:66")]
    assert not run(eng, inv, recs, "new_device")


# -- traffic spike --------------------------------------------------------- #
def test_traffic_spike():
    eng, inv = engine()
    recs = [udp(s, "192.168.1.22", "203.0.113.80", 50000, 443, length=500) for s in range(120)]
    recs += [udp(120 + i / 300, "192.168.1.22", "198.51.100.77", 50001, 80, length=242) for i in range(3000)]
    alerts = run(eng, inv, recs, "traffic_spike")
    assert len(alerts) == 1 and alerts[0].src == "192.168.1.22"


def test_steady_traffic_has_no_spike():
    eng, inv = engine()
    recs = [udp(s * 0.1, "192.168.1.22", "203.0.113.80", 50000, 443, length=1200) for s in range(6000)]
    assert not run(eng, inv, recs, "traffic_spike")


# -- suspicious ports ------------------------------------------------------ #
def test_suspicious_port_needs_established_session():
    eng, inv = engine()
    refused = [tcp(0, "192.168.1.66", "192.168.1.22", 40000, 23, "S"),
               tcp(0.01, "192.168.1.22", "192.168.1.66", 23, 40000, "RA")]
    assert not run(eng, inv, refused, "suspicious_port")

    eng, inv = engine()
    accepted = [tcp(0, "192.168.1.66", "192.168.1.22", 40000, 23, "S"),
                tcp(0.01, "192.168.1.22", "192.168.1.66", 23, 40000, "SA")]
    alerts = run(eng, inv, accepted, "suspicious_port")
    assert len(alerts) == 1 and alerts[0].dst == "192.168.1.22" and alerts[0].severity == "high"


def test_plaintext_mqtt_to_internet():
    eng, inv = engine()
    alerts = run(eng, inv, [tcp(0, "192.168.1.20", "8.8.4.4", 50000, 1883, "S")], "suspicious_port")
    assert any("Unencrypted MQTT" in a.title for a in alerts)


# -- failed connections ---------------------------------------------------- #
def test_refused_connections_to_one_service():
    eng, inv = engine()
    recs = []
    for i in range(12):
        recs += [tcp(i, "192.168.1.66", "192.168.1.21", 41000 + i, 23, "S"),
                 tcp(i + 0.001, "192.168.1.21", "192.168.1.66", 23, 41000 + i, "RA")]
    alerts = run(eng, inv, recs, "failed_connections")
    assert len(alerts) == 1 and alerts[0].details["reasons"] == ["refused"]


def test_unanswered_syns_time_out():
    eng, inv = engine()
    recs = [tcp(i, "192.168.1.20", "192.168.1.10", 42000 + i, 1883, "S") for i in range(20)]
    recs.append(udp(30, "192.168.1.20", "192.168.1.1", 123, 123))  # advances the clock
    alerts = run(eng, inv, recs, "failed_connections")
    assert alerts and alerts[0].details["reasons"] == ["no reply"]


def test_mqtt_auth_bruteforce():
    eng, inv = engine()
    recs = [tcp(i, "192.168.1.10", "192.168.1.66", 1883, 43000 + i, "PA", mqtt_retcode=5) for i in range(6)]
    alerts = run(eng, inv, recs, "failed_connections")
    assert len(alerts) == 1 and alerts[0].severity == "high" and alerts[0].src == "192.168.1.66"


def test_disabled_detector():
    cfg = load_config()["detections"]
    cfg["port_scan"]["enabled"] = False
    eng = DetectionEngine(cfg, Inventory(["192.168.1.0/24"]))
    assert "port_scan" not in [d.name for d in eng.detectors]
