"""Terminal output: the packet table and colour-coded alerts."""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from .models import Alert, PacketRecord

HEADER = f"{'TIME':<9} {'SOURCE':<16} {'DESTINATION':<16} {'PROTOCOL':<8} {'PORT':>5}  {'APP':<9} INFO"
COLOURS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;31m"}
RESET = "\033[0m"
# Inventory events get an indented detail block under the alert line.
DETAIL_RULES = {
    "new_device": (("IP", "ip"), ("MAC", "mac"), ("Vendor", "vendor"), ("First packet", "first_packet")),
    "device_change": (("IP", "ip"), ("MAC", "mac"), ("Vendor", "vendor"), ("Previous IPs", "previous_ips"),
                      ("Previous MAC", "previous_mac"), ("Compared with", "compared_with")),
}


class Printer:
    def __init__(self, show_packets: bool = True, utc: bool = False, colour: bool | None = None,
                 stream=None):
        self.show_packets = show_packets
        self.tz = timezone.utc if utc else None
        self.stream = stream or sys.stdout
        self.colour = self.stream.isatty() if colour is None else colour
        self._header_done = False

    def _time(self, ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=self.tz).strftime("%H:%M:%S")

    def packet(self, rec: PacketRecord) -> None:
        if not self.show_packets:
            return
        if not self._header_done:
            print(HEADER, file=self.stream)
            self._header_done = True
        port = "" if rec.port is None else str(rec.port)
        info = rec.info if len(rec.info) <= 60 else rec.info[:57] + "..."
        print(f"{self._time(rec.ts):<9} {rec.src_ip or rec.src_mac or '?':<16} "
              f"{rec.dst_ip or rec.dst_mac or '?':<16} {rec.protocol:<8} {port:>5}  {rec.app:<9} {info}",
              file=self.stream)

    def alert(self, alert: Alert) -> None:
        tag = f"[ALERT {alert.severity.upper()}]"
        if self.colour:
            tag = f"{COLOURS.get(alert.severity, '')}{tag}{RESET}"
        print(f"{self._time(alert.ts):<9} {tag} {alert.rule}: {alert.title}", file=self.stream)
        for label, key in DETAIL_RULES.get(alert.rule, ()):
            value = alert.details.get(key)
            if value:
                if isinstance(value, list):
                    value = ", ".join(value)
                print(f"{'':<9} {label + ':':<14} {value}", file=self.stream)
