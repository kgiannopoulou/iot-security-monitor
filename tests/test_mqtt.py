"""MQTT tracker and DET-009, driven with hand-made records."""

from iotmon.config import load_config
from iotmon.detections import DetectionEngine
from iotmon.flows import FlowTable
from iotmon.inventory import Inventory
from iotmon.models import PacketRecord
from iotmon.mqtt import MqttTracker, wildcard_scope

BROKER, SENSOR, MOTOR, LAPTOP = "192.168.1.10", "192.168.1.20", "192.168.1.23", "192.168.1.5"
LEARN = 120


def connect(ts, ip, client_id, sport):
    return PacketRecord(ts=ts, protocol="TCP", length=80, src_ip=ip, dst_ip=BROKER, sport=sport, dport=1883,
                        tcp_flags="PA", app="MQTT", meta={"mqtt_types": ["CONNECT"], "mqtt_client_id": client_id,
                                                          "mqtt_username": "devices"})


def connack(ts, ip, sport, code=0):
    return PacketRecord(ts=ts, protocol="TCP", length=60, src_ip=BROKER, dst_ip=ip, sport=1883, dport=sport,
                        tcp_flags="PA", app="MQTT", meta={"mqtt_types": ["CONNACK"], "mqtt_retcode": code})


def publish(ts, ip, topic, value, sport):
    return PacketRecord(ts=ts, protocol="TCP", length=90, src_ip=ip, dst_ip=BROKER, sport=sport, dport=1883,
                        tcp_flags="PA", app="MQTT",
                        meta={"mqtt_types": ["PUBLISH"], "mqtt_topics": [topic],
                              "mqtt_messages": [{"topic": topic, "value": value, "qos": 0, "retain": False}]})


def subscribe(ts, ip, topic, sport):
    return PacketRecord(ts=ts, protocol="TCP", length=70, src_ip=ip, dst_ip=BROKER, sport=sport, dport=1883,
                        tcp_flags="PA", app="MQTT", meta={"mqtt_types": ["SUBSCRIBE"], "mqtt_subscriptions": [topic]})


def baseline_traffic():
    """Two minutes of telemetry: the temperature sensor every 5 s, the motor
    drive (pressure + rpm) every 10 s, the laptop watching factory/motor/rpm."""
    recs = [connect(0, SENSOR, "temp-sensor-01", 40001), connack(0.01, SENSOR, 40001),
            connect(1, MOTOR, "motor-drive-01", 40002), connack(1.01, MOTOR, 40002),
            connect(2, LAPTOP, "hmi-01", 40003), connack(2.01, LAPTOP, 40003),
            subscribe(2.1, LAPTOP, "factory/motor/rpm", 40003)]
    for t in range(5, LEARN, 5):
        recs.append(publish(t, SENSOR, "factory/temperature", "24.6", 40001))
        if t % 10 == 0:
            recs += [publish(t + 0.5, MOTOR, "factory/pressure", "1.8", 40002),
                     publish(t + 0.6, MOTOR, "factory/motor/rpm", "1450", 40002)]
    return recs


def run(recs, rule="mqtt_activity", **overrides):
    cfg = load_config()["detections"]
    for name, values in overrides.items():
        cfg[name].update(values)
    inv = Inventory(["192.168.1.0/24"])
    eng, flows, alerts = DetectionEngine(cfg, inv), FlowTable(), []
    for r in sorted(recs, key=lambda r: r.ts):
        new_device = inv.update(r)
        flows.update(r)
        alerts += eng.process(r, new_device, flows.new_flow)
    alerts += eng.flush()
    return [a for a in alerts if rule is None or a.rule == rule], eng


# -- tracker --------------------------------------------------------------- #
def test_tracker_builds_clients_and_topics():
    _, eng = run(baseline_traffic())
    mqtt = eng.ctx.mqtt
    assert set(mqtt.clients) == {"temp-sensor-01", "motor-drive-01", "hmi-01"}
    sensor = mqtt.clients["temp-sensor-01"]
    assert (sensor.ip, sensor.broker, sensor.username, sensor.connects) == (SENSOR, BROKER, "devices", 1)
    assert sensor.published == {"factory/temperature": 23}
    assert mqtt.clients["hmi-01"].subscriptions == {"factory/motor/rpm"}
    rpm = mqtt.topics["factory/motor/rpm"]
    assert (rpm.last_value, rpm.publishers, rpm.messages) == ("1450", {"motor-drive-01"}, 11)


def test_session_without_connect_is_tracked_by_ip():
    tracker = MqttTracker()
    tracker.update(publish(0, SENSOR, "factory/temperature", "24.6", 40001))
    assert list(tracker.clients) == [f"{SENSOR} (no CONNECT seen)"]


def test_refused_connect_is_counted():
    tracker = MqttTracker()
    tracker.update(connect(0, SENSOR, "x", 40001))
    tracker.update(connack(0.01, SENSOR, 40001, code=5))
    assert tracker.clients["x"].refused == 1


def test_wildcard_scope():
    assert wildcard_scope("#") == "all" and wildcard_scope("$SYS/broker/clients") == "broker"
    assert wildcard_scope("factory/+/rpm") == "partial" and wildcard_scope("factory/temperature") is None


def test_baseline_learns_mqtt_profile():
    _, eng = run(baseline_traffic())
    motor = eng.ctx.baseline.get(MOTOR)
    assert motor.mqtt_client_ids == {"motor-drive-01"}
    assert motor.mqtt_publish == {"factory/pressure", "factory/motor/rpm"}
    assert eng.ctx.baseline.get(SENSOR).peak_mqtt_messages == 13  # one publish every 5 s, 60 s window inclusive


# -- DET-009 --------------------------------------------------------------- #
def test_normal_telemetry_is_quiet():
    recs = baseline_traffic()
    recs += [r for r in baseline_traffic() if setattr(r, "ts", r.ts + LEARN) is None]  # same again, reconnects too
    alerts, _ = run(recs, rule=None)
    assert alerts == []


def test_new_host_connecting_to_broker():
    recs = baseline_traffic() + [connect(LEARN + 5, "192.168.1.66", "mqtt-explorer", 41000)]
    alerts, _ = run(recs)
    assert len(alerts) == 1 and alerts[0].rule_id == "DET-009" and alerts[0].severity == "medium"
    assert alerts[0].title == "New MQTT client: 192.168.1.66 connected to broker 192.168.1.10 as 'mqtt-explorer'"
    assert alerts[0].details["reasons"] == ["host never used MQTT during the baseline"]


def test_known_host_with_new_client_id():
    recs = baseline_traffic() + [connect(LEARN + 5, SENSOR, "debug-client", 41000)]
    alerts, _ = run(recs)
    assert len(alerts) == 1 and "client ID never used" in alerts[0].details["reasons"][0]


def test_message_burst_against_learned_peak():
    recs = baseline_traffic()
    recs += [publish(LEARN + 10 + i * 0.2, SENSOR, "factory/temperature", "24.6", 40001) for i in range(100)]
    alerts, _ = run(recs)
    assert len(alerts) == 1 and alerts[0].title.startswith("MQTT message burst: 192.168.1.20 published 65")
    assert alerts[0].details["baseline_peak"] == 13 and alerts[0].details["threshold"] == 65


def test_burst_below_threshold_is_quiet():
    recs = baseline_traffic()
    recs += [publish(LEARN + 10 + i, SENSOR, "factory/temperature", "24.6", 40001) for i in range(40)]
    assert run(recs)[0] == []  # 40 + normal traffic in a minute: above the 30 floor, below 5 x 13


def test_publishing_another_devices_topic_is_spoofing():
    recs = baseline_traffic() + [publish(LEARN + 5, SENSOR, "factory/motor/rpm", "0", 40001)]
    alerts, _ = run(recs)
    assert len(alerts) == 1 and alerts[0].severity == "high"
    assert alerts[0].details["usual_publishers"] == [MOTOR] and alerts[0].details["value"] == "0"


def test_new_topic_is_medium_and_capped():
    recs = baseline_traffic()
    recs += [publish(LEARN + 5 + i, SENSOR, f"factory/new/{i}", "1", 40001) for i in range(6)]
    alerts, _ = run(recs)
    assert [a.severity for a in alerts] == ["medium"] * 3  # topic_alerts = 3 per cooldown


def test_wildcard_subscription():
    recs = baseline_traffic() + [subscribe(LEARN + 5, LAPTOP, "#", 40003),
                                 subscribe(LEARN + 6, LAPTOP, "factory/motor/rpm", 40003)]  # usual: quiet
    alerts, _ = run(recs)
    assert len(alerts) == 1 and alerts[0].severity == "medium" and alerts[0].details["scope"] == "all"


def test_high_rate_telemetry_is_learned_not_flagged():
    """A drive publishing 2 values every 2 s (60/min) is above the burst floor
    from the start; the learning period must learn that rate, not alert."""
    recs = [connect(0, MOTOR, "motor-drive-01", 40002)]
    for i in range(1, 120):
        t = i * 2
        recs += [publish(t, MOTOR, "factory/pressure", "1.8", 40002),
                 publish(t + 0.01, MOTOR, "factory/motor/rpm", "1450", 40002)]
    alerts, eng = run(recs, rule=None)
    assert alerts == []
    assert eng.ctx.baseline.get(MOTOR).peak_mqtt_messages >= 60
