"""Controlled attack actions for the Docker lab (Week 3 detection tests).

Standard library only, so the file can be piped into any lab container:

    docker exec -i iot-lab-temp-sensor-1 python - flood < lab/scenarios/attacks.py

tools/lab_scenarios.py runs them in order and checks the monitor's alerts.
Every target is a lab address. The one "internet" connection (external) is
sent with IP TTL 1, so the lab gateway discards it: the monitor sees the
attempt on the bridge, and nothing leaves the lab.
"""

from __future__ import annotations

import socket
import sys
import time
import urllib.request

BROKER = "172.28.0.10"
CAMERA = "172.28.0.22"
OUTSIDE = "198.51.100.23"  # RFC 5737 documentation address, never routed

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 502, 554, 1883, 1900, 2323, 3306,
              3389, 5000, 5432, 5555, 5683, 5900, 6667, 7547, 8000, 8080, 8443, 8883]


def hello() -> None:
    """DET-001: a new device's first traffic (one MQTT connection attempt)."""
    with socket.create_connection((BROKER, 1883), timeout=3):
        pass
    print("connected to the broker once")


def scan() -> None:
    """DET-002: TCP connect scan of 30 ports on the broker."""
    found = []
    for port in SCAN_PORTS:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((BROKER, port)) == 0:
                found.append(port)
        time.sleep(0.02)
    print(f"scanned {len(SCAN_PORTS)} ports, open: {found}")


def flood() -> None:
    """DET-003: 30 connections to the broker in about 10 s (reconnect storm)."""
    for _ in range(30):
        with socket.create_connection((BROKER, 1883), timeout=3):
            pass
        time.sleep(0.3)
    print("opened 30 connections to the broker")


def unusual_port() -> None:
    """DET-004: the sensor opens the camera's web UI, then its Telnet service."""
    with urllib.request.urlopen(f"http://{CAMERA}/", timeout=5) as resp:
        print(f"camera web UI: HTTP {resp.status}")
    with socket.create_connection((CAMERA, 23), timeout=5) as s:
        s.recv(64)
        s.sendall(b"root\r\n")
        s.recv(64)
        s.sendall(b"xc3511\r\n")
        time.sleep(1.5)
        print(f"telnet: {s.recv(64)!r}")


def external() -> None:
    """DET-005: a local-only device dials an internet address directly (TTL 1)."""
    for _ in range(2):
        with socket.socket() as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
            s.settimeout(3)
            print(f"connect {OUTSIDE}:8883 -> errno {s.connect_ex((OUTSIDE, 8883))}")


ACTIONS = {"hello": hello, "scan": scan, "flood": flood, "unusual-port": unusual_port, "external": external}

if __name__ == "__main__":
    ACTIONS[sys.argv[1]]()
