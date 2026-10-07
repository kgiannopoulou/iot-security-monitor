"""Each detector in isolation, driven with hand-made records."""

from iotmon.config import load_config
from iotmon.detections import DetectionEngine
from iotmon.flows import FlowTable
from iotmon.inventory import Inventory
from iotmon.models import PacketRecord


def engine(**overrides):
    cfg = load_config()["detections"]
    for name, values in overrides.items():
        cfg[name].update(values)
    inv = Inventory(["192.168.1.0/24"])
    return DetectionEngine(cfg, inv), inv


def run(eng, inv, recs, rule=None):
    flows = FlowTable()
    alerts = []
    for r in recs:
        new_device = inv.update(r)
        flows.update(r)
        alerts += eng.process(r, new_device, flows.new_flow)
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
    half_open = [tcp(0, "192.168.1.66", "192.168.1.22", 40000, 23, "S"),
                 tcp(0.01, "192.168.1.22", "192.168.1.66", 23, 40000, "SA"),
                 tcp(0.02, "192.168.1.66", "192.168.1.22", 40000, 23, "R")]
    assert not run(eng, inv, half_open, "suspicious_port")  # SYN scan: open port, no session

    eng, inv = engine()
    accepted = [tcp(0, "192.168.1.66", "192.168.1.22", 40000, 23, "S"),
                tcp(0.01, "192.168.1.22", "192.168.1.66", 23, 40000, "SA"),
                tcp(0.02, "192.168.1.66", "192.168.1.22", 40000, 23, "A")]
    alerts = run(eng, inv, accepted, "suspicious_port")
    assert len(alerts) == 1 and alerts[0].dst == "192.168.1.22" and alerts[0].severity == "high"
    assert alerts[0].rule_id == "DET-004"


def test_plaintext_mqtt_to_internet():
    eng, inv = engine()
    alerts = run(eng, inv, [tcp(0, "192.168.1.20", "8.8.4.4", 50000, 1883, "S")], "suspicious_port")
    assert any("Unencrypted MQTT" in a.title for a in alerts)


# -- baseline-driven rules (DET-003 / DET-004 / DET-005) ------------------- #
SENSOR, BROKER, CAMERA, PLUG = "192.168.1.20", "192.168.1.10", "192.168.1.22", "192.168.1.21"
LEARN = 120  # default baseline learning period


def session(ts, client, server, dport, sport):
    return [tcp(ts, client, server, sport, dport, "S"),
            tcp(ts + 0.01, server, client, dport, sport, "SA"),
            tcp(ts + 0.02, client, server, sport, dport, "A")]


def dns_answer(ts, client, name, ip, sport):
    return PacketRecord(ts=ts, protocol="UDP", length=90, src_ip="192.168.1.1", dst_ip=client,
                        sport=53, dport=sport, app="DNS", meta={"dns_name": name, "dns_answers": [ip]})


def learned_baseline(offset=0):
    """Two minutes of normal traffic: the sensor reconnects to the broker every
    30 s, the plug resolves and calls its cloud, the laptop opens the camera UI."""
    recs = []
    for i, t in enumerate(range(offset, offset + LEARN, 30)):
        recs += session(t, SENSOR, BROKER, 1883, 41000 + t)
        recs += [udp(t + 1, PLUG, "192.168.1.1", 42000 + t, 53),
                 dns_answer(t + 1.01, PLUG, "api.plug.example", "203.0.113.50", 42000 + t)]
        recs += session(t + 2, PLUG, "203.0.113.50", 443, 43000 + t)
        recs += session(t + 3, "192.168.1.5", CAMERA, 80, 44000 + t)
    return recs


def test_baseline_traffic_is_quiet():
    eng, inv = engine()
    assert not run(eng, inv, learned_baseline() + learned_baseline(LEARN))  # learn, then the same again
    prof = eng.ctx.baseline.get(PLUG)
    assert prof.client_ports == {53, 443} and prof.external_peers == {"203.0.113.50"}
    assert eng.ctx.baseline.get(CAMERA).server_ports == {80}


def test_connection_rate_against_learned_peak():
    eng, inv = engine()
    recs = learned_baseline()
    recs += session(LEARN + 10, SENSOR, BROKER, 1883, 45000)  # normal
    # reconnect storm: 25 MQTT connections in 25 s to one service, so not a scan
    recs += [p for i in range(25) for p in session(LEARN + 20 + i, SENSOR, BROKER, 1883, 46000 + i)]
    alerts = run(eng, inv, recs, "connection_rate")
    assert len(alerts) == 1 and alerts[0].rule_id == "DET-003" and alerts[0].src == SENSOR
    assert alerts[0].details["connections"] == alerts[0].details["threshold"] == 20
    assert alerts[0].details["baseline_peak"] == 3  # sessions at 0, 30 and 60 s share one 60 s window


def test_connection_rate_threshold_scales_with_baseline():
    eng, inv = engine(connection_rate={"min_connections": 8, "peak_factor": 5})
    recs = learned_baseline()  # sensor's learned peak is 3: threshold max(8, 5 * 3) = 15
    recs += [p for i in range(13) for p in session(LEARN + 10 + i, SENSOR, BROKER, 1883, 46000 + i)]
    assert not run(eng, inv, recs, "connection_rate")  # 14 in the window: above the floor, below 5x peak
    recs += session(LEARN + 24, SENSOR, BROKER, 1883, 46100)
    eng, inv = engine(connection_rate={"min_connections": 8, "peak_factor": 5})
    assert run(eng, inv, recs, "connection_rate")[0].details["threshold"] == 15


def test_connection_rate_defers_to_port_scan():
    eng, inv = engine()
    recs = learned_baseline()
    recs += [tcp(LEARN + i * 0.1, "192.168.1.5", CAMERA, 40000, 1000 + i, "S") for i in range(60)]
    assert [a.rule for a in run(eng, inv, recs)] == ["port_scan"]


def test_unusual_port_outside_baseline():
    eng, inv = engine()
    recs = learned_baseline() + session(LEARN + 5, SENSOR, CAMERA, 80, 47000)
    alerts = run(eng, inv, recs, "suspicious_port")
    assert len(alerts) == 1 and alerts[0].severity == "medium"
    assert alerts[0].title.startswith("Unusual port: 192.168.1.20 -> 192.168.1.22:80")
    assert alerts[0].details["client_usual_ports"] == [1883]


def test_new_listening_port_on_known_server():
    eng, inv = engine()
    recs = learned_baseline() + session(LEARN + 5, "192.168.1.5", CAMERA, 8443, 47000)
    alerts = run(eng, inv, recs, "suspicious_port")
    assert len(alerts) == 1 and "never answered on port 8443" in " ".join(alerts[0].details["reasons"])


def test_usual_port_is_quiet():
    eng, inv = engine()
    recs = learned_baseline() + session(LEARN + 5, "192.168.1.5", CAMERA, 80, 47000)
    assert not run(eng, inv, recs, "suspicious_port")


def test_external_connection_from_local_only_device():
    eng, inv = engine()
    recs = learned_baseline() + [tcp(LEARN + 5, SENSOR, "198.51.100.23", 48000, 8883, "S")]
    alerts = run(eng, inv, recs, "external_connection")
    assert len(alerts) == 1 and alerts[0].rule_id == "DET-005" and alerts[0].severity == "high"
    assert alerts[0].details["dns_name"] is None


def test_external_connection_new_resolved_host_is_medium():
    eng, inv = engine()
    recs = learned_baseline()
    recs += [udp(LEARN + 5, PLUG, "192.168.1.1", 48000, 53),
             dns_answer(LEARN + 5.01, PLUG, "updates.other.example", "203.0.113.99", 48000)]
    recs += session(LEARN + 5.1, PLUG, "203.0.113.99", 443, 48001)
    recs += session(LEARN + 6, PLUG, "203.0.113.50", 443, 48002)  # usual cloud peer: fine
    alerts = run(eng, inv, recs, "external_connection")
    assert len(alerts) == 1 and alerts[0].severity == "medium"
    assert alerts[0].details["dns_name"] == "updates.other.example"


def test_external_fanout_is_one_alert():
    eng, inv = engine()
    recs = learned_baseline()
    recs += [tcp(LEARN + i, PLUG, f"203.0.113.{100 + i}", 49000 + i, 443 + i, "S") for i in range(15)]
    alerts = run(eng, inv, recs, "external_connection")
    assert [a.title.split(":")[0] for a in alerts] == ["Unexpected external connection"] * 3 + ["External fan-out"]
    assert alerts[-1].details["destinations_observed"] == 10


def test_private_and_multicast_peers_are_not_external():
    inv = Inventory(["192.168.1.0/24"])
    assert inv.is_external("8.8.8.8") and inv.is_external("198.51.100.23")
    for ip in ("10.1.2.3", "172.20.0.1", "192.168.5.5", "239.255.255.250", "255.255.255.255", "169.254.1.1"):
        assert not inv.is_external(ip), ip


def test_alert_evidence_record():
    eng, inv = engine()
    recs = [tcp(i * 0.1, "192.168.1.66", CAMERA, 40000, 1000 + i, "S") for i in range(27)]
    evidence = run(eng, inv, recs, "port_scan")[0].as_dict()
    assert evidence["rule"] == "DET-002" and evidence["severity"] == "HIGH"
    assert evidence["source_ip"] == "192.168.1.66" and evidence["ports_observed"] == 15
    assert evidence["timestamp"].endswith("Z") and evidence["window_s"] == 60


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
