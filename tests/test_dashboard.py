from iotmon.config import load_config
from iotmon.dashboard.app import create_app
from iotmon.models import Alert, PacketRecord
from iotmon.pipeline import Monitor
from iotmon.storage import Storage


def test_api_endpoints(tmp_path):
    db = tmp_path / "x.db"
    mon = Monitor(load_config(), Storage(db, reset=True))
    mon.process(PacketRecord(ts=60, protocol="UDP", length=90, src_ip="192.168.1.20", dst_ip="192.168.1.1",
                             src_mac="24:0a:c4:00:00:20", sport=123, dport=123, app="NTP"))
    mon._emit([Alert(61, "port_scan", "high", "test alert", src="192.168.1.66")])
    mon.close()

    client = create_app(db).test_client()
    s = client.get("/api/summary").get_json()
    assert (s["devices"], s["alerts"], s["packets"]) == (1, 1, 1)
    assert client.get("/api/alerts").get_json()[0]["title"] == "test alert"
    devices = client.get("/api/devices").get_json()
    assert devices[0]["ips"] == "192.168.1.20" and devices[0]["connections"] == 1
    assert client.get("/api/traffic").get_json() == {"minutes": [60], "series": {"NTP": [1]}}
    assert client.get("/").status_code == 200


def test_missing_database_is_empty(tmp_path):
    client = create_app(tmp_path / "missing.db").test_client()
    assert client.get("/api/summary").get_json()["alerts"] == 0
    assert client.get("/api/alerts").get_json() == []


def test_mqtt_endpoint(tmp_path):
    db = tmp_path / "m.db"
    mon = Monitor(load_config(), Storage(db, reset=True))
    mon.process(PacketRecord(ts=0, protocol="TCP", length=80, src_ip="192.168.1.20", dst_ip="192.168.1.10",
                             sport=40001, dport=1883, tcp_flags="PA", app="MQTT",
                             meta={"mqtt_types": ["CONNECT"], "mqtt_client_id": "temp-sensor-01"}))
    mon.process(PacketRecord(ts=5, protocol="TCP", length=90, src_ip="192.168.1.20", dst_ip="192.168.1.10",
                             sport=40001, dport=1883, tcp_flags="PA", app="MQTT",
                             meta={"mqtt_types": ["PUBLISH"], "mqtt_messages": [
                                 {"topic": "factory/temperature", "value": "24.6", "qos": 0, "retain": False}]}))
    mon.close()
    m = create_app(db).test_client().get("/api/mqtt").get_json()
    assert m["clients"][0]["client_id"] == "temp-sensor-01" and m["clients"][0]["messages"] == 1
    assert m["topics"] == [{"topic": "factory/temperature", "first_seen": 5.0, "last_seen": 5.0, "messages": 1,
                            "last_value": "24.6", "publishers": "temp-sensor-01"}]
