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
