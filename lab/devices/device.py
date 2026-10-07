"""Simulated IoT devices for the lab. One image, several roles:

    temp_sensor  publishes temperature telemetry over MQTT every 5 s
    smart_plug   publishes power readings, listens for on/off commands,
                 checks in with its vendor cloud (DNS lookup + HTTP) every 60 s
    ip_camera    serves a web UI on :80, has Telnet open on :23 (a classic
                 IoT weakness), uploads a snapshot to the cloud every 30 s
    cloud        the "vendor cloud": accepts check-ins and uploads on :80
    admin        a workstation that opens the camera web UI every 60 s

Role and settings come from environment variables (see docker-compose.yml).
"""

from __future__ import annotations

import json
import os
import random
import socket
import socketserver
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "temp_sensor")
BROKER = os.environ.get("MQTT_BROKER", "172.28.0.10")
MQTT_USER = os.environ.get("MQTT_USER", "devices")
MQTT_PASS = os.environ.get("MQTT_PASS", "S3nsor!2026")
DNS_SERVER = os.environ.get("DNS_SERVER", "172.28.0.53")
CLOUD_NAME = os.environ.get("CLOUD_NAME", "api.vendor-cloud.lab")
CAMERA = os.environ.get("CAMERA", "172.28.0.22")


def log(msg: str) -> None:
    print(f"[{ROLE}] {msg}", flush=True)


def resolve(name: str) -> str:
    import dns.resolver

    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [DNS_SERVER]
    return r.resolve(name, "A")[0].to_text()


def mqtt_client(client_id: str):
    import paho.mqtt.client as mqtt

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    client.username_pw_set(MQTT_USER, MQTT_PASS)
    while True:
        try:
            client.connect(BROKER, 1883, keepalive=60)
            break
        except OSError as e:
            log(f"broker not ready ({e}), retrying")
            time.sleep(3)
    client.loop_start()
    return client


def http(method: str, url: str, body: bytes | None = None) -> int:
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": f"iot-{ROLE}/1.0", "Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
            return resp.status
    except OSError as e:
        log(f"{method} {url} failed: {e}")
        return 0


# --------------------------------------------------------------------------- #
def temp_sensor() -> None:
    client = mqtt_client(os.environ.get("CLIENT_ID", "temp-sensor-01"))
    while True:
        reading = {"c": round(21 + random.random() * 2, 2), "ts": int(time.time())}
        client.publish("factory/line1/temp", json.dumps(reading))
        time.sleep(5)


def smart_plug() -> None:
    client = mqtt_client(os.environ.get("CLIENT_ID", "smart-plug-01"))
    state = {"on": True}

    def on_message(_c, _u, msg):
        state["on"] = msg.payload.decode() == "on"
        log(f"command {msg.topic}: {msg.payload!r}")

    client.on_message = on_message
    client.subscribe("factory/line1/plug/cmd")
    last_checkin = 0.0
    while True:
        watts = round(38 + random.random() * 6, 1) if state["on"] else 0.0
        client.publish("factory/line1/plug/power", json.dumps({"w": watts, "on": state["on"]}))
        if time.time() - last_checkin > 60:
            try:
                ip = resolve(CLOUD_NAME)
                http("POST", f"http://{ip}/checkin", json.dumps({"device": "plug-01", "fw": "1.4.2"}).encode())
            except Exception as e:  # noqa: BLE001 - keep the device alive
                log(f"check-in failed: {e}")
            last_checkin = time.time()
        time.sleep(10)


class FakeTelnet(socketserver.StreamRequestHandler):
    """Prompts for credentials and always refuses - enough to look like an
    exposed Telnet service on the wire, with nothing behind it."""

    def handle(self):
        try:
            for _ in range(3):
                self.wfile.write(b"camera login: ")
                if not self.rfile.readline(64):
                    return
                self.wfile.write(b"Password: ")
                self.rfile.readline(64)
                time.sleep(1)
                self.wfile.write(b"Login incorrect\r\n")
        except OSError:
            pass


class CameraWeb(BaseHTTPRequestHandler):
    def do_GET(self):
        body = os.urandom(30_000) if self.path.startswith("/snapshot") else b"<h1>IP Camera</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg" if len(body) > 100 else "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def ip_camera() -> None:
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    telnet = socketserver.ThreadingTCPServer(("0.0.0.0", 23), FakeTelnet)
    threading.Thread(target=telnet.serve_forever, daemon=True).start()
    web = ThreadingHTTPServer(("0.0.0.0", 80), CameraWeb)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    log("web UI on :80, telnet on :23")
    while True:
        try:
            ip = resolve(CLOUD_NAME)
            http("POST", f"http://{ip}/upload", os.urandom(18_000 + random.randint(0, 4000)))
        except Exception as e:  # noqa: BLE001
            log(f"upload failed: {e}")
        time.sleep(30)


class CloudAPI(BaseHTTPRequestHandler):
    def _ok(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        body = b'{"status": "ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _ok

    def log_message(self, fmt, *args):
        log(f"{self.client_address[0]} {fmt % args}")


def cloud() -> None:
    log("vendor cloud API on :80")
    ThreadingHTTPServer(("0.0.0.0", 80), CloudAPI).serve_forever()


def admin() -> None:
    while True:
        time.sleep(60)
        http("GET", f"http://{CAMERA}/snapshot.jpg")


ROLES = {"temp_sensor": temp_sensor, "smart_plug": smart_plug, "ip_camera": ip_camera,
         "cloud": cloud, "admin": admin}

if __name__ == "__main__":
    log(f"starting on {socket.gethostname()}")
    ROLES[ROLE]()
