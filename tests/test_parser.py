from scapy.contrib.mqtt import MQTT, MQTTConnack, MQTTPublish
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from iotmon.models import service_port
from iotmon.parser import parse_packet

ETH = Ether(src="24:0a:c4:00:00:20", dst="dc:a6:32:00:00:10")


def roundtrip(pkt):
    """Serialise and re-dissect, exactly as a packet read from the wire."""
    return parse_packet(Ether(bytes(pkt)))


def test_service_port_prefers_known_service():
    assert service_port(51000, 1883) == 1883
    assert service_port(1883, 51000) == 1883
    assert service_port(50000, 9001) == 9001
    assert service_port(None, 80) is None


def test_mqtt_publish():
    pkt = (ETH / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=50000, dport=1883, flags="PA")
           / MQTT(type=3) / MQTTPublish(topic="factory/line1/temp", value='{"c": 21.5}'))
    rec = roundtrip(pkt)
    assert (rec.protocol, rec.port, rec.app) == ("TCP", 1883, "MQTT")
    assert rec.info == 'PUBLISH factory/line1/temp = {"c": 21.5}'
    assert rec.meta["mqtt_topics"] == ["factory/line1/temp"]
    assert rec.meta["mqtt_messages"] == [{"topic": "factory/line1/temp", "value": '{"c": 21.5}',
                                          "qos": 0, "retain": False}]
    assert rec.src_mac == "24:0a:c4:00:00:20"


def test_mqtt_connack_refused():
    pkt = (ETH / IP(src="192.168.1.10", dst="192.168.1.66") / TCP(sport=1883, dport=40000, flags="PA")
           / MQTT(type=2) / MQTTConnack(retcode=5))
    rec = roundtrip(pkt)
    assert rec.meta["mqtt_retcode"] == 5
    assert rec.is_response
    assert "not authorized" in rec.info


def test_dns_query_and_answer():
    q = (ETH / IP(src="192.168.1.21", dst="192.168.1.1") / UDP(sport=53000, dport=53)
         / DNS(rd=1, qd=DNSQR(qname="api.smartplug.example")))
    rec = roundtrip(q)
    assert (rec.protocol, rec.port, rec.app) == ("UDP", 53, "DNS")
    assert rec.info == "query api.smartplug.example"
    a = (ETH / IP(src="192.168.1.1", dst="192.168.1.21") / UDP(sport=53, dport=53000)
         / DNS(qr=1, qd=DNSQR(qname="api.smartplug.example"),
               an=DNSRR(rrname="api.smartplug.example", rdata="203.0.113.50")))
    assert roundtrip(a).info == "answer api.smartplug.example -> 203.0.113.50"


def test_http_request():
    pkt = (ETH / IP(src="192.168.1.5", dst="192.168.1.22") / TCP(sport=50123, dport=80, flags="PA")
           / Raw(b"GET /snapshot.jpg HTTP/1.1\r\nHost: 192.168.1.22\r\n\r\n"))
    rec = roundtrip(pkt)
    assert rec.app == "HTTP"
    assert rec.info == "GET 192.168.1.22/snapshot.jpg"


def test_arp_and_tcp_flags():
    arp = parse_packet(Ether(src="b8:27:eb:00:00:66", dst="ff:ff:ff:ff:ff:ff")
                       / ARP(op=1, psrc="192.168.1.66", pdst="192.168.1.10"))
    assert arp.protocol == "ARP" and arp.meta["arp_op"] == "request"
    syn = parse_packet(ETH / IP(src="192.168.1.66", dst="192.168.1.22") / TCP(sport=40000, dport=23, flags="S"))
    assert syn.is_syn and not syn.is_synack and syn.app == "TELNET"
    sa = parse_packet(ETH / IP(src="192.168.1.22", dst="192.168.1.66") / TCP(sport=23, dport=40000, flags="SA"))
    assert sa.is_synack and sa.is_response


def test_icmp_unreachable_quotes_port():
    pkt = (ETH / IP(src="198.51.100.77", dst="192.168.1.22") / ICMP(type=3, code=3)
           / IP(src="192.168.1.22", dst="198.51.100.77") / UDP(sport=40000, dport=80))
    rec = roundtrip(pkt)
    assert rec.protocol == "ICMP" and rec.meta["unreachable_port"] == 80


def test_garbage_payload_does_not_raise():
    pkt = (ETH / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=50000, dport=1883, flags="PA")
           / Raw(b"\xff" * 7))
    rec = roundtrip(pkt)
    assert rec.protocol == "TCP" and rec.port == 1883
