"""Core data types shared by every stage of the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Well-known ports seen on IoT / OT networks. Used to label traffic and to
# decide which side of a conversation is the "service" (server) side.
KNOWN_SERVICES: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    102: "S7COMM",
    123: "NTP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    502: "MODBUS",
    554: "RTSP",
    1883: "MQTT",
    1900: "SSDP",
    2323: "TELNET-ALT",
    3389: "RDP",
    4444: "METERPRETER",
    5353: "MDNS",
    5555: "ADB",
    5683: "COAP",
    6667: "IRC",
    7547: "TR-069",
    8080: "HTTP-ALT",
    8883: "MQTT-TLS",
    20000: "DNP3",
    44818: "ENIP",
    47808: "BACNET",
}

SEVERITIES = ("low", "medium", "high", "critical")

# Detector name -> (rule ID, short name). DET-001..005 are the core detection
# rules; 006..008 are supporting rules that add evidence to an incident.
RULES: dict[str, tuple[str, str]] = {
    "new_device": ("DET-001", "New/unrecognized device"),
    "port_scan": ("DET-002", "Port scanning behaviour"),
    "connection_rate": ("DET-003", "Abnormal connection rate"),
    "suspicious_port": ("DET-004", "Communication with unusual ports"),
    "external_connection": ("DET-005", "Unexpected external connection"),
    "traffic_spike": ("DET-006", "Traffic volume spike"),
    "failed_connections": ("DET-007", "Repeated failed connections"),
    "device_change": ("DET-008", "Device address change"),
}


def rule_id(rule: str) -> str:
    return RULES.get(rule, (rule, ""))[0]


def service_port(sport: int | None, dport: int | None) -> int | None:
    """Return the port that identifies the *service* in a conversation.

    A client talks from a random ephemeral port to a fixed service port, so
    for both the request (eph -> 1883) and the reply (1883 -> eph) we want
    1883. Known services win; otherwise the lower port is the better guess.
    """
    if sport is None or dport is None:
        return None
    if dport in KNOWN_SERVICES:
        return dport
    if sport in KNOWN_SERVICES:
        return sport
    return min(sport, dport)


@dataclass(slots=True)
class PacketRecord:
    """One observed packet, reduced to the fields a monitor cares about."""

    ts: float
    protocol: str  # ARP, TCP, UDP, ICMP, IPv6, OTHER
    length: int
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    sport: int | None = None
    dport: int | None = None
    tcp_flags: str = ""
    app: str = ""  # application protocol label (MQTT, DNS, HTTP, ...)
    info: str = ""  # human-readable detail (DNS query, MQTT topic, ...)
    # Structured app-layer facts the detectors use (e.g. mqtt_retcode).
    meta: dict = field(default_factory=dict)

    @property
    def port(self) -> int | None:
        return service_port(self.sport, self.dport)

    @property
    def is_response(self) -> bool:
        """True when the packet travels *from* the service side."""
        p = self.port
        return p is not None and p == self.sport and p != self.dport

    @property
    def is_syn(self) -> bool:
        return self.protocol == "TCP" and "S" in self.tcp_flags and "A" not in self.tcp_flags

    @property
    def is_synack(self) -> bool:
        return self.protocol == "TCP" and "S" in self.tcp_flags and "A" in self.tcp_flags

    @property
    def is_rst(self) -> bool:
        return self.protocol == "TCP" and "R" in self.tcp_flags

    def as_row(self) -> dict:
        d = asdict(self)
        d.pop("meta")
        d["port"] = self.port
        d["time"] = datetime.fromtimestamp(self.ts, tz=timezone.utc).isoformat()
        return d


@dataclass(slots=True)
class Alert:
    ts: float
    rule: str
    severity: str
    title: str
    src: str | None = None
    dst: str | None = None
    mitre: str = ""
    details: dict = field(default_factory=dict)

    @property
    def rule_id(self) -> str:
        return rule_id(self.rule)

    def as_dict(self) -> dict:
        """The alert as an evidence record: who, what, when, and the numbers
        that made the rule fire (flattened from details)."""
        d = {
            "timestamp": datetime.fromtimestamp(self.ts, tz=timezone.utc).isoformat(timespec="milliseconds")[:-6] + "Z",
            "rule": self.rule_id,
            "rule_name": self.rule,
            "severity": self.severity.upper(),
            "source_ip": self.src,
            "destination_ip": self.dst,
            "description": self.title,
            "mitre": self.mitre,
        }
        d.update({k: v for k, v in self.details.items() if k not in d})
        return d
