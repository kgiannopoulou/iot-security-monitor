"""Generate samples/iot-lab.pcap: a deterministic, synthetic capture of a
small IoT network, with a normal baseline followed by a Mirai-style attack.

Running the generator again yields byte-identical output (fixed seed and
fixed start time), so tests and documentation can quote exact results.

Timeline (seconds from start)
    0-300   baseline: sensors publish MQTT telemetry, plug checks in with its
            cloud API over HTTPS, camera uploads snapshots, admin laptop
            views the camera web UI, NTP / DNS / ARP background noise
    300     rogue Raspberry Pi joins, ARP-sweeps the subnet
    310     SYN scan of the camera (finds Telnet 23 and HTTP 80 open)
    330     Telnet logins to the camera
    345     Telnet attempts against the smart plug, refused (RST)
    360     MQTT credential brute force against the broker
    395     camera (now "compromised") connects to an IRC C2 server
    400     camera floods an external host with UDP (DDoS participation)
    -480    baseline traffic carries on underneath the attack until the end

All addresses are RFC 1918 (lab) or RFC 5737 documentation ranges.
"""

from __future__ import annotations

import logging
import random
import sys
from pathlib import Path

for _name in ("scapy.runtime", "scapy.loading"):
    logging.getLogger(_name).setLevel(logging.ERROR)

from scapy.contrib.mqtt import MQTT, MQTTConnack, MQTTConnect, MQTTPublish
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.ntp import NTP
from scapy.packet import Raw
from scapy.utils import wrpcap

START = 1791369000.0  # 2026-10-07 10:30:00 UTC
SEED = 1883

GW = ("192.168.1.1", "50:c7:bf:00:00:01")          # router: DNS forwarder, NTP, gateway
BROKER = ("192.168.1.10", "dc:a6:32:00:00:10")      # Mosquitto on a Raspberry Pi
LAPTOP = ("192.168.1.5", "3c:52:82:00:00:05")       # admin workstation
TEMP = ("192.168.1.20", "24:0a:c4:00:00:20")        # ESP32 temperature sensor
PLUG = ("192.168.1.21", "24:0a:c4:00:00:21")        # ESP8266 smart plug
CAMERA = ("192.168.1.22", "44:19:b6:00:00:22")      # IP camera
ROGUE = ("192.168.1.66", "b8:27:eb:00:00:66")       # attacker's Raspberry Pi
CLOUD = "203.0.113.50"                              # plug vendor cloud (TEST-NET-3)
CAM_CLOUD = "203.0.113.80"                          # camera vendor cloud
C2 = "198.51.100.23"                                # IRC C2 (TEST-NET-2)
VICTIM = "198.51.100.77"                            # DDoS target
BCAST = "ff:ff:ff:ff:ff:ff"

LOCAL = {ip: mac for ip, mac in (GW, BROKER, LAPTOP, TEMP, PLUG, CAMERA, ROGUE)}


def l2(src_ip: str, dst_ip: str):
    """Ethernet header: off-subnet destinations are reached via the gateway MAC."""
    src_mac = LOCAL.get(src_ip, GW[1])
    dst_mac = LOCAL.get(dst_ip, GW[1])
    return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, ttl=64)


class Capture:
    def __init__(self):
        self.packets = []
        self.rng = random.Random(SEED)
        self._eph = 49152

    def add(self, t: float, pkt) -> None:
        pkt.time = START + t
        self.packets.append(pkt)

    def eph(self) -> int:
        self._eph = 49152 + (self._eph - 49152 + self.rng.randint(1, 97)) % 16000
        return self._eph

    def jitter(self, spread: float = 0.4) -> float:
        return self.rng.uniform(-spread, spread)

    # -- TCP helpers ------------------------------------------------------ #
    def tcp_session(self, t, client, server, dport, c2s=(), s2c=(), close=True, sport=None):
        """Handshake, alternating request/response payloads, FIN teardown."""
        sport = sport or self.eph()
        cseq, sseq = self.rng.randint(1, 2**31), self.rng.randint(1, 2**31)
        dt = 0.002
        self.add(t, l2(client, server) / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
        self.add(t + dt, l2(server, client) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
        t += 2 * dt
        self.add(t, l2(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        cseq, sseq = cseq + 1, sseq + 1
        for i in range(max(len(c2s), len(s2c))):
            if i < len(c2s):
                t += dt
                payload = c2s[i]
                self.add(t, l2(client, server) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / payload)
                cseq += len(payload)
            if i < len(s2c):
                t += dt
                payload = s2c[i]
                self.add(t, l2(server, client) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / payload)
                sseq += len(payload)
        if close:
            t += dt
            self.add(t, l2(client, server) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
            self.add(t + dt, l2(server, client) / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
            self.add(t + 2 * dt, l2(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        return sport, cseq, sseq

    def tls_bulk(self, t, client, server, upload: int):
        """An HTTPS upload: opaque TLS records split into ~1400 byte segments."""
        chunks = [Raw(bytes(self.rng.getrandbits(8) for _ in range(min(1400, upload - i))))
                  for i in range(0, upload, 1400)]
        self.tcp_session(t, client, server, 443, c2s=chunks, s2c=[Raw(b"\x17\x03\x03\x00\x20" + bytes(32))])

    def dns(self, t, client, name, answer):
        sport = self.eph()
        txid = self.rng.randint(1, 65535)
        self.add(t, l2(client, GW[0]) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name)))
        self.add(t + 0.012, l2(GW[0], client) / UDP(sport=53, dport=sport) /
                 DNS(id=txid, qr=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=300, rdata=answer)))

    def ntp(self, t, client):
        # Explicit timestamps (seconds since 1900): scapy would otherwise use "now".
        now = START + t + 2208988800
        self.add(t, l2(client, GW[0]) / UDP(sport=123, dport=123) / NTP(version=4, mode=3, orig=0, sent=now))
        self.add(t + 0.003, l2(GW[0], client) / UDP(sport=123, dport=123) /
                 NTP(version=4, mode=4, stratum=2, orig=now, recv=now, ref=now - 60, sent=now + 0.001))

    def arp(self, t, asker, target):
        self.add(t, Ether(src=asker[1], dst=BCAST) / ARP(op=1, hwsrc=asker[1], psrc=asker[0], pdst=target))
        if target in LOCAL:
            self.add(t + 0.001, Ether(src=LOCAL[target], dst=asker[1]) /
                     ARP(op=2, hwsrc=LOCAL[target], psrc=target, hwdst=asker[1], pdst=asker[0]))


def mqtt_connect(client_id: str, user: str, password: str):
    return MQTT(type=1) / MQTTConnect(protoname="MQTT", protolevel=4, usernameflag=1, passwordflag=1,
                                      cleansess=1, klive=60, clientId=client_id, username=user, password=password)


def mqtt_publish(topic: str, value: str):
    return MQTT(type=3) / MQTTPublish(topic=topic, value=value)


def baseline(cap: Capture, t0: float, t1: float) -> None:
    rng = cap.rng

    # Persistent MQTT sessions: opened once, then telemetry on the same socket.
    if t0 == 0:
        for dev, cid in ((TEMP, "temp-sensor-01"), (PLUG, "smart-plug-01")):
            cap.ntp(0.5 + rng.random(), dev[0])
            cap.arp(1 + rng.random(), (dev[0], dev[1]), BROKER[0])
        cap.mqtt_ports = {}
        for dev, cid, t in ((TEMP, "temp-sensor-01", 2.0), (PLUG, "smart-plug-01", 3.0)):
            sport, cseq, sseq = cap.tcp_session(
                t, dev[0], BROKER[0], 1883,
                c2s=[mqtt_connect(cid, "devices", "S3nsor!2026")],
                s2c=[MQTT(type=2) / MQTTConnack(retcode=0)], close=False)
            cap.mqtt_ports[dev[0]] = [sport, cseq, sseq]
        cap.ntp(4.2, CAMERA[0])
        cap.ntp(6.1, LAPTOP[0])
        cap.arp(7.0, LAPTOP, CAMERA[0])

    def publish(t, dev, topic, value):
        sport, cseq, sseq = cap.mqtt_ports[dev[0]]
        payload = mqtt_publish(topic, value)
        cap.add(t, l2(dev[0], BROKER[0]) / TCP(sport=sport, dport=1883, flags="PA", seq=cseq, ack=sseq) / payload)
        cseq += len(payload)
        cap.add(t + 0.004, l2(BROKER[0], dev[0]) / TCP(sport=1883, dport=sport, flags="A", seq=sseq, ack=cseq))
        cap.mqtt_ports[dev[0]][1] = cseq

    t = t0
    while t < t1:
        # temperature sensor: every 5 s (after its MQTT session is up)
        if int(t) % 5 == 0 and t >= 5:
            publish(t + 0.1 + cap.jitter(0.05), TEMP, "factory/line1/temp",
                    f'{{"c": {21 + rng.random() * 2:.2f}}}')
        # smart plug: power reading every 10 s
        if int(t) % 10 == 3 and t >= 5:
            publish(t + cap.jitter(0.1), PLUG, "factory/line1/plug/power",
                    f'{{"w": {38 + rng.random() * 6:.1f}, "on": true}}')
        # smart plug cloud check-in every 60 s: DNS lookup then HTTPS
        if int(t) % 60 == 15:
            cap.dns(t, PLUG[0], "api.smartplug.example", CLOUD)
            cap.tls_bulk(t + 0.05, PLUG[0], CLOUD, upload=600 + rng.randint(0, 200))
        # camera snapshot upload every 30 s
        if int(t) % 30 == 20:
            if int(t) % 120 == 20:
                cap.dns(t - 0.1, CAMERA[0], "upload.camcloud.example", CAM_CLOUD)
            cap.tls_bulk(t, CAMERA[0], CAM_CLOUD, upload=18000 + rng.randint(0, 4000))
        # admin views the camera web UI every 60 s
        if int(t) % 60 == 40:
            cap.tcp_session(t, LAPTOP[0], CAMERA[0], 80,
                            c2s=[Raw(b"GET /snapshot.jpg HTTP/1.1\r\nHost: 192.168.1.22\r\n\r\n")],
                            s2c=[Raw(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n" + bytes(1300))] +
                                [Raw(bytes(1400)) for _ in range(6)])
        # occasional ARP refresh from the gateway
        if int(t) % 45 == 30:
            cap.arp(t + 0.5, GW, rng.choice([TEMP[0], PLUG[0], CAMERA[0], BROKER[0]]))
        t += 1


def attack(cap: Capture) -> None:
    rng = cap.rng
    # 300: rogue Pi joins and ARP-sweeps .1-.30
    for i, host in enumerate(range(1, 31)):
        cap.arp(300 + i * 0.05, ROGUE, f"192.168.1.{host}")

    # 310: SYN scan of the camera, 40 common ports; 23 and 80 are open
    ports = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 554, 993, 995, 1080, 1433,
             1723, 1883, 2323, 3306, 3389, 5000, 5060, 5432, 5555, 5900, 6667, 7547, 8000, 8008, 8080,
             8081, 8443, 8888, 9000, 9100, 37777]
    sport = 40125
    for i, port in enumerate(ports):
        t = 310 + i * 0.02
        cap.add(t, l2(ROGUE[0], CAMERA[0]) / TCP(sport=sport, dport=port, flags="S", seq=1000))
        if port in (23, 80):
            cap.add(t + 0.001, l2(CAMERA[0], ROGUE[0]) / TCP(sport=port, dport=sport, flags="SA", seq=5000, ack=1001))
            cap.add(t + 0.002, l2(ROGUE[0], CAMERA[0]) / TCP(sport=sport, dport=port, flags="R", seq=1001))
        else:
            cap.add(t + 0.001, l2(CAMERA[0], ROGUE[0]) / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=1001))

    # 330: Telnet logins to the camera (default credentials guessing)
    for i, (user, pw) in enumerate([("admin", "admin"), ("root", "12345"), ("root", "xc3511"), ("root", "vizxv")]):
        cap.tcp_session(330 + i * 2, ROGUE[0], CAMERA[0], 23,
                        c2s=[Raw(f"{user}\r\n".encode()), Raw(f"{pw}\r\n".encode())],
                        s2c=[Raw(b"login: "), Raw(b"Password: "),
                             Raw(b"Login incorrect\r\n" if i < 3 else b"# ")])

    # 345: Telnet against the smart plug - closed, refused 12 times
    for i in range(12):
        t = 345 + i * 0.8
        sp = cap.eph()
        cap.add(t, l2(ROGUE[0], PLUG[0]) / TCP(sport=sp, dport=23, flags="S", seq=77))
        cap.add(t + 0.001, l2(PLUG[0], ROGUE[0]) / TCP(sport=23, dport=sp, flags="RA", seq=0, ack=78))

    # 360: MQTT credential brute force against the broker
    for i, pw in enumerate(["admin", "password", "mosquitto", "123456", "devices", "iot", "raspberry", "changeme"]):
        cap.tcp_session(360 + i * 1.5, ROGUE[0], BROKER[0], 1883,
                        c2s=[mqtt_connect(f"probe-{i}", "devices", pw)],
                        s2c=[MQTT(type=2) / MQTTConnack(retcode=5)])

    # 395: compromised camera phones home to IRC C2
    cap.dns(394.8, CAMERA[0], "cnc.badbot.example", C2)
    cap.tcp_session(395, CAMERA[0], C2, 6667,
                    c2s=[Raw(b"NICK cam22\r\nUSER cam22 0 * :cam\r\n"), Raw(b"JOIN #botnet\r\n")],
                    s2c=[Raw(b":c2 001 cam22 :welcome\r\n"), Raw(b":op PRIVMSG #botnet :!udp 198.51.100.77 8\r\n")],
                    close=False)

    # 400: UDP flood, 300 packets/s for 8 s
    for i in range(2400):
        t = 400 + i / 300
        cap.add(t, l2(CAMERA[0], VICTIM) / UDP(sport=rng.randint(1024, 65535), dport=rng.choice([53, 80, 443, 123])) /
                Raw(bytes(200)))

    # ICMP unreachable noise from the victim's firewall (rate-limited)
    for i in range(3):
        quoted = IP(src=CAMERA[0], dst=VICTIM) / UDP(sport=40000 + i, dport=80)
        cap.add(401 + i, l2(VICTIM, CAMERA[0]) / ICMP(type=3, code=3) / quoted)


def build() -> list:
    cap = Capture()
    baseline(cap, 0, 300)
    attack(cap)
    baseline(cap, 300, 480)
    cap.packets.sort(key=lambda p: p.time)
    return cap.packets


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples" / "iot-lab.pcap"
    packets = build()
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"wrote {len(packets)} packets to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
