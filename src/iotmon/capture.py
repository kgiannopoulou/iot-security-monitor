"""Packet sources: a saved pcap file or a live interface.

Both yield PacketRecords, so everything downstream is identical whether the
monitor is replaying evidence or watching the wire.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Iterator

from scapy.utils import PcapReader

from .models import PacketRecord
from .parser import parse_packet


def read_pcap(path: str, limit: int | None = None) -> Iterator[PacketRecord]:
    with PcapReader(path) as reader:
        for i, pkt in enumerate(reader):
            if limit is not None and i >= limit:
                return
            yield parse_packet(pkt)


def sniff_live(
    iface: str | None,
    bpf: str | None = None,
    limit: int | None = None,
    timeout: float | None = None,
) -> Iterator[PacketRecord]:
    """Capture from a live interface (needs root / CAP_NET_RAW, or Npcap on Windows).

    scapy's AsyncSniffer runs in its own thread; packets are handed over
    through a queue so the caller can process them as a normal iterator.
    """
    from scapy.sendrecv import AsyncSniffer

    q: queue.Queue = queue.Queue(maxsize=10_000)
    done = object()

    sniffer = AsyncSniffer(
        iface=iface,
        filter=bpf,
        store=False,
        count=limit or 0,
        prn=lambda p: q.put(p),
    )

    def _watch() -> None:
        sniffer.join()
        q.put(done)

    sniffer.start()
    threading.Thread(target=_watch, daemon=True).start()
    if timeout:
        timer = threading.Timer(timeout, sniffer.stop)
        timer.daemon = True
        timer.start()
    try:
        while True:
            item = q.get()
            if item is done:
                break
            yield parse_packet(item)
    finally:
        if sniffer.running:
            sniffer.stop()
