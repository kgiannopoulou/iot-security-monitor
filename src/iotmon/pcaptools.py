"""Carve the packets related to an alert out of its source capture, for
inspection in Wireshark (Week 8). This closes the investigation loop:

    alert -> source/destination -> related traffic -> inspect PCAP -> findings

Only works for alerts from a `read` run whose pcap is still on disk (a live
capture is not retained). The scapy import is lazy so the rest of the CLI
does not pay for it.
"""

from __future__ import annotations

from pathlib import Path


def carve(source: str | Path, out: str | Path, hosts: set[str], ts: float,
          window: float = 30.0) -> int:
    """Write every packet in `source` that involves one of `hosts` within
    `window` seconds of `ts` to `out`. Returns the packet count."""
    from scapy.utils import PcapReader, PcapWriter
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    hosts = {h for h in hosts if h}
    lo, hi = ts - window, ts + window
    kept = 0
    reader = PcapReader(str(source))
    # Preserve the source link-layer type (Ethernet) so the result dissects correctly.
    writer = PcapWriter(str(out), linktype=reader.linktype, sync=True)
    try:
        with reader:
            for pkt in reader:
                t = float(pkt.time)
                if t < lo or t > hi:
                    continue
                if IP in pkt:
                    ends = {pkt[IP].src, pkt[IP].dst}
                elif IPv6 in pkt:
                    ends = {pkt[IPv6].src, pkt[IPv6].dst}
                else:
                    continue
                if not hosts or ends & hosts:
                    writer.write(pkt)
                    kept += 1
    finally:
        writer.close()
    return kept
