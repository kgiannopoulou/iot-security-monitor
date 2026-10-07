"""Generate samples/scenarios/*.pcap: one controlled test scenario per core
detection rule (DET-001 to DET-005), plus a near-miss scenario that stays
just under the thresholds and must stay silent.

Every scenario is the same small IoT network as samples/iot-lab.pcap: four
minutes of normal traffic (the first two are the monitor's learning period),
with one misbehaviour injected at t = 180 s. Each scenario states which rules
it must trigger. tests/test_scenarios.py and tools/run_scenarios.py check
that exactly those rules, and nothing else, fire.

    python tools/generate_scenarios.py          # (re)write samples/scenarios/
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from generate_sample_pcap import (BROKER, CAMERA, GW, LAPTOP, PLUG, ROGUE, START, TEMP, Capture, baseline,
                                  l2, mqtt_connect)
from scapy.contrib.mqtt import MQTT, MQTTConnack
from scapy.layers.inet import TCP, UDP
from scapy.layers.ntp import NTP
from scapy.packet import Raw
from scapy.utils import wrpcap

OUT_DIR = Path(__file__).resolve().parent.parent / "samples" / "scenarios"
T = 180          # attack start: after the 120 s learning period
DURATION = 240   # seconds of baseline traffic around it


@dataclass(frozen=True)
class Scenario:
    name: str
    expect: tuple[str, ...]  # rule IDs that must fire, and no others
    story: str
    inject: Callable[[Capture], None]

    @property
    def path(self) -> Path:
        return OUT_DIR / f"{self.name}.pcap"


# --------------------------------------------------------------------------- #
def new_device(cap: Capture) -> None:
    """An unknown Raspberry Pi is plugged into the switch and starts talking."""
    cap.arp(T, ROGUE, GW[0])
    now = START + T + 1 + 2208988800
    cap.add(T + 1, l2(ROGUE[0], GW[0]) / UDP(sport=123, dport=123) / NTP(version=4, mode=3, orig=0, sent=now))
    cap.dns(T + 2, ROGUE[0], "raspberrypi.local.example", "192.168.1.1")


def port_scan(cap: Capture) -> None:
    """The admin laptop SYN-scans the broker (half-open: RST after SYN-ACK)."""
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 502, 554, 1883, 1900, 2323, 3306, 3389,
             5000, 5432, 5555, 5683, 5900, 6667, 7547, 8000, 8080, 8443, 8883]
    sport = 51515
    for i, port in enumerate(ports):
        t = T + i * 0.05
        cap.add(t, l2(LAPTOP[0], BROKER[0]) / TCP(sport=sport, dport=port, flags="S", seq=4242))
        if port == 1883:
            cap.add(t + 0.001, l2(BROKER[0], LAPTOP[0]) / TCP(sport=port, dport=sport, flags="SA", seq=9000, ack=4243))
            cap.add(t + 0.002, l2(LAPTOP[0], BROKER[0]) / TCP(sport=sport, dport=port, flags="R", seq=4243))
        else:
            cap.add(t + 0.001, l2(BROKER[0], LAPTOP[0]) / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=4243))


def connection_flood(cap: Capture) -> None:
    """The temperature sensor's firmware gets stuck in a reconnect loop: 30
    complete MQTT sessions to its usual broker in 30 s. Same peer, same port,
    valid credentials: only the rate is abnormal."""
    for i in range(30):
        cap.tcp_session(T + i, TEMP[0], BROKER[0], 1883,
                        c2s=[mqtt_connect("temp-sensor-01", "devices", "S3nsor!2026")],
                        s2c=[MQTT(type=2) / MQTTConnack(retcode=0)])


def unusual_port(cap: Capture) -> None:
    """The (compromised) temperature sensor, which only ever spoke MQTT and
    NTP, opens the camera's web UI and then its Telnet service."""
    cap.tcp_session(T, TEMP[0], CAMERA[0], 80,
                    c2s=[Raw(b"GET / HTTP/1.1\r\nHost: 192.168.1.22\r\n\r\n")],
                    s2c=[Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>IP Camera</h1>")])
    cap.tcp_session(T + 5, TEMP[0], CAMERA[0], 23,
                    c2s=[Raw(b"root\r\n"), Raw(b"xc3511\r\n")],
                    s2c=[Raw(b"camera login: "), Raw(b"Password: "), Raw(b"Login incorrect\r\n")])


def external_connection(cap: Capture) -> None:
    """The local-only temperature sensor tries to reach an internet host by
    IP (blocked: no reply, three retries), and the smart plug looks up and
    calls a host that is not its vendor cloud."""
    for i, delay in enumerate((0, 1, 3)):
        cap.add(T + delay, l2(TEMP[0], "198.51.100.23") / TCP(sport=50123, dport=8883, flags="S", seq=777))
    cap.dns(T + 10, PLUG[0], "fw.unknown-cdn.example", "203.0.113.99")
    cap.tls_bulk(T + 10.1, PLUG[0], "203.0.113.99", upload=900)


def near_miss(cap: Capture) -> None:
    """The same kinds of activity, kept just under every threshold: the
    laptop probes 12 broker ports (scan threshold 15), the sensor reconnects
    12 times in a minute (rate threshold 20), and the plug's cloud check-in
    happens one extra time. None of it should alert."""
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445]):
        t = T + i * 0.05
        cap.add(t, l2(LAPTOP[0], BROKER[0]) / TCP(sport=51516, dport=port, flags="S", seq=4242))
        cap.add(t + 0.001, l2(BROKER[0], LAPTOP[0]) / TCP(sport=port, dport=51516, flags="RA", seq=0, ack=4243))
    for i in range(12):
        cap.tcp_session(T + 5 + i * 4, TEMP[0], BROKER[0], 1883,
                        c2s=[mqtt_connect("temp-sensor-01", "devices", "S3nsor!2026")],
                        s2c=[MQTT(type=2) / MQTTConnack(retcode=0)])
    cap.dns(T + 30, PLUG[0], "api.smartplug.example", "203.0.113.50")
    cap.tls_bulk(T + 30.1, PLUG[0], "203.0.113.50", upload=700)


SCENARIOS = [
    Scenario("det-001-new-device", ("DET-001",),
             "Unknown Raspberry Pi joins the network (ARP, NTP, DNS)", new_device),
    Scenario("det-002-port-scan", ("DET-002",),
             "Admin laptop SYN-scans 30 ports on the MQTT broker in 1.5 s", port_scan),
    Scenario("det-003-connection-flood", ("DET-003",),
             "Sensor opens 30 MQTT sessions to its own broker in 30 s (reconnect storm)", connection_flood),
    Scenario("det-004-unusual-port", ("DET-004",),
             "Sensor opens HTTP (unusual for it) and Telnet (high-risk) sessions to the camera", unusual_port),
    Scenario("det-005-external-connection", ("DET-005",),
             "Local-only sensor dials 198.51.100.23 by IP; plug calls an unknown host", external_connection),
    Scenario("near-miss-below-thresholds", (),
             "12-port probe, 12 reconnects/min, extra cloud check-in: all under threshold", near_miss),
]


def build(scenario: Scenario) -> list:
    cap = Capture()
    baseline(cap, 0, DURATION)
    scenario.inject(cap)
    cap.packets.sort(key=lambda p: p.time)
    return cap.packets


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for sc in SCENARIOS:
        packets = build(sc)
        wrpcap(str(sc.path), packets)
        print(f"{sc.path.name:<34} {len(packets):>5} packets  expects {', '.join(sc.expect) or 'no alerts'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
