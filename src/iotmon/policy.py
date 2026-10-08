"""OT zones and the communication policy (Week 7).

Industrial networks are defended by *segmentation*: devices live in zones
(the Purdue model: OT/control vs IT/enterprise), and only certain
conversations are meant to cross between them. An engineering workstation
may talk to a PLC; a laptop in the office network, or an IP camera, must
not. This module turns a small piece of configuration into those two
questions:

    which zone is this device in?     zone_of(ip)
    is this connection allowed?        allowed(src, dst, plc_ips)

Configuration (the `ot:` section of config.yaml):

    zones:            zone name -> list of CIDRs / IPs   (OT, IT, ...)
    assets:           ip -> {role, label}                (declare known OT assets)
    policy.allow:     initiator role -> [target roles]   (the allowlist)
    modbus.allowed_clients / writers:  roles that may read / write a PLC
    expected_protocols: application protocols normal inside the OT zone

Everything is optional: with no `ot:` section the OT rules simply never
fire, so IoT-only deployments are unaffected.
"""

from __future__ import annotations

import ipaddress


def _net(s: str):
    return ipaddress.ip_network(s, strict=False)


class ZonePolicy:
    def __init__(self, cfg: dict | None = None):
        cfg = cfg or {}
        self.zone_nets: dict[str, list] = {z: [_net(n) for n in nets] for z, nets in cfg.get("zones", {}).items()}
        self.assets: dict[str, dict] = {ip: dict(a) for ip, a in cfg.get("assets", {}).items()}
        self.allow: dict[str, set[str]] = {src: set(dsts) for src, dsts in cfg.get("policy", {}).get("allow", {}).items()}
        modbus = cfg.get("modbus", {})
        self.modbus_clients: set[str] = set(modbus.get("allowed_clients", []))
        self.modbus_writers: set[str] = set(modbus.get("writers", []))
        self.expected_protocols: set[str] = set(cfg.get("expected_protocols", []))
        self.enabled = bool(self.zone_nets or self.assets)

    # -- zones and roles --------------------------------------------------- #
    def zone_of(self, ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for zone, nets in self.zone_nets.items():
            if any(addr in n for n in nets):
                return zone
        return None

    def is_ot(self, ip: str | None) -> bool:
        return self.zone_of(ip) == "OT"

    def role_of(self, ip: str | None, plc_ips: set[str] | None = None) -> str:
        """Declared role, else inferred: a Modbus server in OT is a PLC;
        otherwise the device's zone, lowercased, or 'unknown'."""
        if ip and ip in self.assets and self.assets[ip].get("role"):
            return self.assets[ip]["role"]
        if plc_ips and ip in plc_ips and self.is_ot(ip):
            return "plc"
        zone = self.zone_of(ip)
        return zone.lower() if zone else "unknown"

    def label_of(self, ip: str | None) -> str:
        return self.assets.get(ip or "", {}).get("label", "")

    def is_declared(self, ip: str | None) -> bool:
        return ip in self.assets

    # -- the policy -------------------------------------------------------- #
    def allowed(self, src: str | None, dst: str | None, plc_ips: set[str] | None = None) -> bool:
        """May `src` initiate a connection to `dst`? Only meaningful when dst is
        in the OT zone; other targets are not this policy's concern (returns True)."""
        if not self.is_ot(dst):
            return True
        if self.zone_of(src) == "OT":
            return True  # intra-OT traffic; the Modbus allowlist polices it further
        src_role = self.role_of(src, plc_ips)
        dst_role = self.role_of(dst, plc_ips)
        return dst_role in self.allow.get(src_role, set())

    def modbus_client_allowed(self, ip: str | None, plc_ips: set[str] | None = None) -> bool:
        if not self.modbus_clients:
            return True  # no allowlist configured: don't flag anyone
        return self.role_of(ip, plc_ips) in self.modbus_clients or ip in self.modbus_clients

    def modbus_writer_allowed(self, ip: str | None, plc_ips: set[str] | None = None) -> bool:
        if not self.modbus_writers:
            return self.modbus_client_allowed(ip, plc_ips)
        return self.role_of(ip, plc_ips) in self.modbus_writers or ip in self.modbus_writers
