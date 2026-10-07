"""Passive device inventory: which hosts live on the monitored network.

Devices are identified by MAC address (stable on the local segment) and
fall back to IP when no Ethernet header is available. Only addresses inside
the configured lab networks become devices; remote peers (cloud services,
DNS resolvers on the internet) are tracked as peers, not as inventory.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .models import PacketRecord

# Minimal offline OUI table: first three MAC octets -> vendor.
OUI_VENDORS = {
    "24:0a:c4": "Espressif (ESP32/ESP8266)",
    "30:ae:a4": "Espressif (ESP32/ESP8266)",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "50:c7:bf": "TP-Link",
    "44:19:b6": "Hikvision",
    "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",
    "00:1b:1b": "Siemens",
    "3c:52:82": "HP",
}

BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

ROLE_BY_SERVICE = [
    (1883, "MQTT broker"),
    (8883, "MQTT broker"),
    (502, "Modbus/TCP server (PLC)"),
    (53, "DNS server"),
    (554, "IP camera (RTSP)"),
    (123, "NTP server"),
    (80, "Web interface"),
]


def vendor_for(mac: str | None) -> str:
    if not mac:
        return "unknown"
    vendor = OUI_VENDORS.get(mac[:8])
    if vendor:
        return vendor
    # Bit 1 of the first octet = locally administered (VMs, containers, randomised MACs)
    if int(mac[:2], 16) & 0x02:
        return "locally administered (virtual / randomised)"
    return "unknown"


@dataclass(slots=True)
class Device:
    key: str
    mac: str | None
    first_seen: float
    last_seen: float
    ips: set = field(default_factory=set)
    vendor: str = "unknown"
    name: str = ""
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    protocols: set = field(default_factory=set)
    services: set = field(default_factory=set)  # ports this device answered on
    peers: set = field(default_factory=set)
    mqtt_publisher: bool = False

    @property
    def role(self) -> str:
        for port, role in ROLE_BY_SERVICE:
            if port in self.services:
                if role == "Web interface" and 23 in self.services:
                    return "IP camera / embedded web device"
                return role
        if self.mqtt_publisher:
            return "MQTT client (sensor/actuator)"
        if self.protocols & {"HTTP", "HTTPS"}:
            return "client"
        return "unclassified"

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "mac": self.mac,
            "ips": sorted(self.ips),
            "vendor": self.vendor,
            "name": self.name,
            "role": self.role,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "protocols": sorted(self.protocols),
            "services": sorted(self.services),
            "peers": len(self.peers),
        }


class Inventory:
    def __init__(self, lab_networks: list[str]):
        self.networks = [ipaddress.ip_network(n) for n in lab_networks]
        self.devices: dict[str, Device] = {}
        self._by_ip: dict[str, str] = {}

    def is_local(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_multicast or addr.is_unspecified or str(addr).endswith(".255"):
            return False
        return any(addr in n for n in self.networks)

    def lookup(self, ip: str | None) -> Device | None:
        key = self._by_ip.get(ip or "")
        return self.devices.get(key) if key else None

    def update(self, rec: PacketRecord) -> Device | None:
        """Account for a packet. Returns the Device if it was seen for the first time."""
        new = None
        if self.is_local(rec.src_ip):
            mac = rec.src_mac if rec.src_mac not in BROADCAST_MACS else None
            dev, created = self._get_or_create(rec.src_ip, mac, rec.ts)
            if created:
                new = dev
            dev.last_seen = rec.ts
            dev.packets_sent += 1
            dev.bytes_sent += rec.length
            # A bare SYN or RST says nothing about what the device really speaks
            # (a port scan would otherwise "teach" us dozens of protocols).
            if rec.app and not (rec.is_syn or rec.is_rst):
                dev.protocols.add(rec.app)
            if rec.dst_ip:
                dev.peers.add(rec.dst_ip)
            if rec.is_response and rec.port is not None and not rec.is_rst:
                dev.services.add(rec.port)
            if "mqtt_client_id" in rec.meta:
                dev.name = rec.meta["mqtt_client_id"]
            if rec.meta.get("mqtt_topics") and not rec.is_response:
                dev.mqtt_publisher = True

        if rec.protocol != "ARP":
            dst = self.lookup(rec.dst_ip)
            if dst is not None:
                dst.packets_recv += 1
                dst.bytes_recv += rec.length
                if rec.src_ip:
                    dst.peers.add(rec.src_ip)
        return new

    def _get_or_create(self, ip: str, mac: str | None, ts: float) -> tuple[Device, bool]:
        key = mac or ip
        dev = self.devices.get(key)
        created = False
        if dev is None:
            # An IP-keyed placeholder may exist from before we saw its MAC.
            placeholder = self.devices.pop(ip, None) if mac else None
            if placeholder is not None:
                dev = placeholder
                dev.key, dev.mac, dev.vendor = key, mac, vendor_for(mac)
            else:
                dev = Device(key=key, mac=mac, first_seen=ts, last_seen=ts, vendor=vendor_for(mac))
                created = True
            self.devices[key] = dev
        dev.ips.add(ip)
        self._by_ip[ip] = key
        return dev, created
