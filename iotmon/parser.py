"""Turn raw scapy packets into PacketRecords.

Layer by layer, mirroring the TCP/IP model:

    Ethernet (MACs) -> ARP | IPv4/IPv6 (IPs) -> TCP/UDP/ICMP (ports, flags)
    -> application (MQTT, DNS, HTTP, ...)

Anything we cannot decode is still recorded at the deepest layer we
understood, so the monitor never silently drops traffic.
"""

from __future__ import annotations

from scapy.contrib.mqtt import CONTROL_PACKET_TYPE, MQTT  # importing binds TCP/1883
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP, UDPerror
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.ntp import NTP
from scapy.packet import Packet

from .models import KNOWN_SERVICES, PacketRecord, service_port

ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}
MQTT_CONNACK_CODES = {
    0: "accepted",
    1: "bad protocol version",
    2: "identifier rejected",
    3: "server unavailable",
    4: "bad username or password",
    5: "not authorized",
}


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return "" if value is None else str(value)


def parse_packet(pkt: Packet) -> PacketRecord:
    rec = PacketRecord(ts=float(pkt.time), protocol="OTHER", length=len(pkt))

    if Ether in pkt:
        rec.src_mac = pkt[Ether].src.lower()
        rec.dst_mac = pkt[Ether].dst.lower()

    if ARP in pkt:
        arp = pkt[ARP]
        rec.protocol = "ARP"
        rec.app = "ARP"
        rec.src_ip, rec.dst_ip = arp.psrc, arp.pdst
        if arp.op == 1:
            rec.info = f"who-has {arp.pdst} tell {arp.psrc}"
            rec.meta["arp_op"] = "request"
        else:
            rec.info = f"{arp.psrc} is-at {arp.hwsrc}"
            rec.meta["arp_op"] = "reply"
        return rec

    if IP in pkt:
        rec.src_ip, rec.dst_ip = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        rec.src_ip, rec.dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        rec.protocol = "IPv6"
    else:
        return rec

    if TCP in pkt:
        tcp = pkt[TCP]
        rec.protocol = "TCP"
        rec.sport, rec.dport = int(tcp.sport), int(tcp.dport)
        rec.tcp_flags = str(tcp.flags)
    elif UDP in pkt:
        udp = pkt[UDP]
        rec.protocol = "UDP"
        rec.sport, rec.dport = int(udp.sport), int(udp.dport)
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        rec.protocol = "ICMP"
        rec.app = "ICMP"
        rec.info = ICMP_TYPES.get(int(icmp.type), f"type {icmp.type}")
        rec.meta["icmp_type"] = int(icmp.type)
        rec.meta["icmp_code"] = int(icmp.code)
        # A "port unreachable" quotes the UDP header it refers to.
        if int(icmp.type) == 3 and UDPerror in icmp:
            rec.meta["unreachable_port"] = int(icmp[UDPerror].dport)
        return rec
    else:
        return rec

    port = service_port(rec.sport, rec.dport)
    rec.app = KNOWN_SERVICES.get(port, "")
    try:
        _parse_application(pkt, rec)
    except Exception:  # malformed / truncated payloads must never stop capture
        rec.info = rec.info or "undecodable payload"
    if not rec.info and rec.protocol == "TCP":
        rec.info = f"[{rec.tcp_flags}]"
    return rec


def _parse_application(pkt: Packet, rec: PacketRecord) -> None:
    if DNS in pkt:
        dns = pkt[DNS]
        rec.app = "MDNS" if rec.port == 5353 else "DNS"
        name = _text(dns.qd[0].qname).rstrip(".") if dns.qd else "?"
        if dns.qr == 0:
            rec.info = f"query {name}"
        else:
            answers = [_text(rr.rdata) for rr in (dns.an or []) if getattr(rr, "type", None) in (1, 28)]  # A/AAAA
            rec.info = f"answer {name} -> {', '.join(answers) or 'no records'}"
            rec.meta["dns_answers"] = answers
        rec.meta["dns_name"] = name
        return

    if MQTT in pkt:
        rec.app = "MQTT"
        parts = []
        layer = pkt[MQTT]
        # One TCP segment can carry several MQTT control packets.
        while isinstance(layer, MQTT):
            ptype = CONTROL_PACKET_TYPE.get(int(layer.type), str(layer.type))
            body = layer.payload
            if ptype == "CONNECT":
                client_id = _text(body.clientId)
                rec.meta["mqtt_client_id"] = client_id
                user = _text(getattr(body, "username", b"")) if body.usernameflag else ""
                parts.append(f"CONNECT id={client_id}" + (f" user={user}" if user else ""))
            elif ptype == "CONNACK":
                code = int(body.retcode)
                rec.meta["mqtt_retcode"] = code
                parts.append(f"CONNACK {MQTT_CONNACK_CODES.get(code, code)}")
            elif ptype == "PUBLISH":
                topic = _text(body.topic)
                rec.meta.setdefault("mqtt_topics", []).append(topic)
                parts.append(f"PUBLISH {topic}")
            elif ptype == "SUBSCRIBE":
                topics = [_text(t.topic) for t in getattr(body, "topics", [])]
                parts.append(f"SUBSCRIBE {','.join(topics)}")
            else:
                parts.append(ptype)
            layer = body.payload if body is not None else None
        rec.info = "; ".join(parts)
        return

    if NTP in pkt and rec.port == 123:
        mode = int(getattr(pkt[NTP], "mode", 0))
        rec.info = {3: "client request", 4: "server reply"}.get(mode, f"mode {mode}")
        return

    if HTTPRequest in pkt:
        req = pkt[HTTPRequest]
        rec.app = "HTTP"
        rec.info = f"{_text(req.Method)} {_text(req.Host)}{_text(req.Path)}"
        rec.meta["http_host"] = _text(req.Host)
        return
    if HTTPResponse in pkt:
        resp = pkt[HTTPResponse]
        rec.app = "HTTP"
        rec.info = f"{_text(resp.Status_Code)} {_text(resp.Reason_Phrase)}"
        return

    if rec.app in ("HTTPS", "MQTT-TLS") and rec.protocol == "TCP" and len(pkt[TCP].payload):
        rec.info = f"TLS record, {len(pkt[TCP].payload)} bytes (encrypted)"
