"""Asset register: the device inventory, kept between runs.

The in-memory Inventory only knows what one capture showed. The register is
a JSON file (default data/inventory.json) that remembers every device the
monitor has ever seen, so "new device" means *new to this network*, not just
new since the monitor started.

Each asset has a status:

    approved  known and expected (learned from trusted traffic, or approved by hand)
    pending   seen by the monitor but not yet reviewed; it alerted once as new
    new       first seen during the current run (becomes pending when saved)

Assets are keyed by MAC address because IPs change (DHCP) and MACs, on the
local segment, mostly do not. Devices seen without an Ethernet header fall
back to their IP as the key.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from .inventory import Device

DEFAULT_REGISTER = "data/inventory.json"
STATUSES = ("approved", "pending")
COUNTERS = ("connections", "packets", "bytes")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


class AssetRegister:
    def __init__(self, path: str | Path = DEFAULT_REGISTER):
        self.path = Path(path)
        self.assets: dict[str, dict] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.assets = data.get("assets", {})
        # Counters as loaded, so merging the same run again (a live monitor saves
        # every 30 s) recomputes the totals instead of adding the run twice.
        self._loaded = {k: (_ts(a["last_seen"]), {c: a[c] for c in COUNTERS}) for k, a in self.assets.items()}

    def __len__(self) -> int:
        return len(self.assets)

    def __contains__(self, key: str) -> bool:
        return key in self.assets

    def get(self, key: str) -> dict | None:
        return self.assets.get(key)

    def find(self, mac_or_ip: str) -> str | None:
        """Resolve a MAC or IP to an asset key."""
        needle = mac_or_ip.lower()
        if needle in self.assets:
            return needle
        for key, a in self.assets.items():
            if needle in a["ips"]:
                return key
        return None

    def status_of(self, dev: Device) -> str:
        asset = self.assets.get(dev.key)
        return asset["status"] if asset else "new"

    def merge(self, devices: list[Device], status: str | Callable[[Device], str] = "pending") -> list[str]:
        """Fold one run's devices into the register. Returns the keys that were added.

        `status` is given to devices not yet in the register (or computed per device).

        Counters (connections, packets, bytes) add up across runs, except when
        the run overlaps time already recorded for that device, which means the
        same traffic was replayed; then the larger value is kept. Merging the
        same run more than once gives the same result.
        """
        added = []
        for dev in devices:
            obs = dev.as_dict()
            asset = self.assets.get(dev.key)
            if asset is None:
                asset = {
                    "ip": dev.last_ip or None,
                    "ips": obs["ips"],
                    "mac": dev.mac,
                    "vendor": dev.vendor,
                    "name": dev.name,
                    "role": dev.role,
                    "first_seen": _iso(dev.first_seen),
                    "last_seen": _iso(dev.last_seen),
                    "protocols": obs["protocols"],
                    "services": obs["services"],
                    "connections": dev.connections,
                    "packets": dev.packets_sent + dev.packets_recv,
                    "bytes": dev.bytes_sent + dev.bytes_recv,
                    "status": status(dev) if callable(status) else status,
                }
                self.assets[dev.key] = asset
                added.append(dev.key)
            else:
                loaded_last, base = self._loaded.get(dev.key, (None, dict.fromkeys(COUNTERS, 0)))
                replay = loaded_last is not None and dev.first_seen <= loaded_last
                for counter, value in (("connections", dev.connections),
                                       ("packets", dev.packets_sent + dev.packets_recv),
                                       ("bytes", dev.bytes_sent + dev.bytes_recv)):
                    asset[counter] = max(base[counter], value) if replay else base[counter] + value
                asset["ips"] = sorted(set(asset["ips"]) | dev.ips)
                if dev.last_seen >= _ts(asset["last_seen"]):
                    asset["ip"] = dev.last_ip or asset["ip"]
                    asset["last_seen"] = _iso(dev.last_seen)
                asset["first_seen"] = _iso(min(dev.first_seen, _ts(asset["first_seen"])))
                asset["protocols"] = sorted(set(asset["protocols"]) | dev.protocols)
                asset["services"] = sorted(set(asset["services"]) | dev.services)
                asset["name"] = dev.name or asset["name"]
                if dev.role != "unclassified":
                    asset["role"] = dev.role
            dev.status = asset["status"]
        return added

    def set_status(self, mac_or_ip: str, status: str) -> str | None:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        key = self.find(mac_or_ip)
        if key:
            self.assets[key]["status"] = status
        return key

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "assets": dict(sorted(self.assets.items(), key=lambda kv: kv[1]["first_seen"])),
        }
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def by_ip(self) -> dict[str, dict]:
        """The inventory keyed by current IP address, as an analyst usually reads it."""
        view = {}
        for key, a in self.assets.items():
            entry = {k: v for k, v in a.items() if k != "ip"}
            entry["key"] = key
            view[a["ip"] or key] = entry
        return view
