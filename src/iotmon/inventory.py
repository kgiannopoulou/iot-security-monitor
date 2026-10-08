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
    last_ip: str = ""  # the address it used most recently
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
    modbus_server: bool = False  # answered on Modbus/TCP (a PLC)
    modbus_client: bool = False  # sent Modbus requests (engineering workstation / HMI)
    connections: int = 0  # flows (TCP or UDP conversations) this device took part in
    status: str = ""  # asset-register status: approved / pending / new ("" = no register)
    zone: str = ""  # OT / IT / ... from the zone policy ("" = no policy / unassigned)
    policy_role: str = ""  # role declared in the OT policy (plc, hmi, engineering_workstation)
    policy_label: str = ""  # human label from the OT policy
    risk_score: int = 0

    @property
    def role(self) -> str:
        if self.policy_role:
            return {"plc": "PLC (Modbus/TCP server)", "hmi": "HMI panel",
                    "engineering_workstation": "Engineering workstation"}.get(self.policy_role, self.policy_role)
        for port, role in ROLE_BY_SERVICE:
            if port in self.services:
                if role == "Web interface" and 23 in self.services:
                    return "IP camera / embedded web device"
                return role
        if self.modbus_client:
            return "Modbus/TCP client (engineering / HMI)"
        if self.mqtt_publisher:
            return "MQTT client (sensor/actuator)"
        if self.protocols & {"HTTP", "HTTPS"}:
            return "client"
        return "unclassified"

    @property
    def device_type(self) -> str:
        """A short machine-readable type for the asset record (brief's `device_type`)."""
        if self.policy_role == "plc" or self.modbus_server:
            return "PLC"
        if self.policy_role:
            return {"hmi": "HMI", "engineering_workstation": "EWS"}.get(self.policy_role, self.policy_role.upper())
        if self.modbus_client:
            return "Modbus client"
        if 1883 in self.services or 8883 in self.services:
            return "MQTT broker"
        if self.mqtt_publisher:
            return "IoT sensor/actuator"
        if 80 in self.services and 23 in self.services:
            return "IP camera"
        return "host"

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
            "connections": self.connections,
            "status": self.status,
            "zone": self.zone,
            "device_type": self.device_type,
            "risk_score": self.risk_score,
        }


# Private address space: not the monitored lab, but not "the internet" either
# (other site VLANs, the IT network). Override with network.internal_networks.
DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]


class Inventory:
    def __init__(self, lab_networks: list[str], internal_networks: list[str] | None = None):
        self.networks = [ipaddress.ip_network(n) for n in lab_networks]
        self.internal = [ipaddress.ip_network(n) for n in
                         (DEFAULT_INTERNAL if internal_networks is None else internal_networks)]
        self.policy = None  # set by the Monitor; gives devices their OT zone, role and risk
        self.devices: dict[str, Device] = {}
        self._by_ip: dict[str, str] = {}
        # Address changes caused by the last update(), read by the device_change rule:
        # ("ip_change", device, new_ip, previous_ips) or ("ip_conflict", device, ip, previous_owner)
        self.changes: list[tuple] = []
        # Connections to local addresses that have not sent a packet yet (a server
        # is usually seen as a destination first); credited when the device appears.
        self._pending_connections: dict[str, int] = {}

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

    def is_external(self, ip: str | None) -> bool:
        """A routable address outside the lab and the internal networks.

        Documentation ranges (RFC 5737, used by the sample captures) count as
        external; broadcast, multicast, link-local and loopback never do."""
        if not ip or self.is_local(ip):
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if (addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_link_local
                or str(addr) == "255.255.255.255"):
            return False
        return not any(addr in n for n in self.internal if n.version == addr.version)

    def lookup(self, ip: str | None) -> Device | None:
        key = self._by_ip.get(ip or "")
        return self.devices.get(key) if key else None

    def update(self, rec: PacketRecord) -> Device | None:
        """Account for a packet. Returns the Device if it was seen for the first time."""
        new = None
        self.changes = []
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
            if rec.app == "MODBUS":
                if rec.is_response:
                    dev.modbus_server = True
                elif rec.dport == 502:
                    dev.modbus_client = True
            if self.policy is not None:
                dev.zone = self.policy.zone_of(rec.src_ip) or ""
                dev.policy_role = self.policy.assets.get(rec.src_ip, {}).get("role", "")
                dev.policy_label = self.policy.label_of(rec.src_ip)
                dev.risk_score = self._risk(dev)

        if rec.protocol != "ARP":
            dst = self.lookup(rec.dst_ip)
            if dst is not None:
                dst.packets_recv += 1
                dst.bytes_recv += rec.length
                if rec.src_ip:
                    dst.peers.add(rec.src_ip)
        return new

    # Risk weighting. A documented heuristic (0-100), not a probability: a
    # device's zone and role set the baseline, exposure raises it. Used to
    # rank the asset register, and it is shown in each asset's record.
    ZONE_RISK = {"OT": 45, "IoT": 25, "IT": 15}
    TYPE_RISK = {"PLC": 25, "MQTT broker": 15, "EWS": 12, "HMI": 12, "IP camera": 10}

    def _risk(self, dev: Device) -> int:
        score = self.ZONE_RISK.get(dev.zone, 15 if dev.zone else 15)
        score += self.TYPE_RISK.get(dev.device_type, 0)
        if 23 in dev.services:  # exposed Telnet
            score += 15
        if any(self.is_external(p) for p in dev.peers):  # talks to / from the internet
            score += 15
        if dev.status in ("pending", "new"):  # not yet reviewed
            score += 10
        return max(0, min(100, score))

    def count_flow(self, client_ip: str, server_ip: str) -> None:
        """A new conversation started: one more connection for each local end."""
        for ip in {client_ip, server_ip}:
            dev = self.lookup(ip)
            if dev is not None:
                dev.connections += 1
            elif self.is_local(ip):
                self._pending_connections[ip] = self._pending_connections.get(ip, 0) + 1

    def _get_or_create(self, ip: str, mac: str | None, ts: float) -> tuple[Device, bool]:
        key = mac or ip
        dev = self.devices.get(key)
        created = False
        owner = self.devices.get(self._by_ip.get(ip, ""))
        if mac and owner is not None and owner.mac and owner.mac != mac:
            # The address was already bound to another network card.
            self.changes.append(("ip_conflict", None, ip, owner))
        elif dev is not None and ip not in dev.ips:
            self.changes.append(("ip_change", dev, ip, sorted(dev.ips)))
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
        dev.last_ip = ip
        dev.connections += self._pending_connections.pop(ip, 0)
        self._by_ip[ip] = key
        self.changes = [(kind, d or dev, *rest) for kind, d, *rest in self.changes]
        return dev, created
