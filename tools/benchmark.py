"""Throughput benchmark: packets per second through each stage of the
pipeline, on the bundled captures.

    python tools/benchmark.py                 # table (markdown)
    python tools/benchmark.py --repeat 5      # best of 5 runs per stage
    python tools/benchmark.py --json

Stages, each measured on its own so the bottleneck is visible:

    read      scapy reads and dissects the pcap        (PcapReader)
    parse     dissected packet -> PacketRecord          (parser.py)
    detect    inventory, flows, the 15 rules             (Monitor, no storage)
    store     detect + SQLite / JSONL writes            (Monitor with Storage)
    end2end   `iotmon read` as a user runs it           (read + parse + store)

The scapy layer dominates, which is why the README recommends Zeek or
Suricata as the parser for anything faster than one IoT segment.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from scapy import __version__ as scapy_version  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from iotmon.config import load_config  # noqa: E402
from iotmon.parser import parse_packet  # noqa: E402
from iotmon.pipeline import Monitor  # noqa: E402
from iotmon.storage import Storage  # noqa: E402

CAPTURES = [ROOT / "samples" / "iot-lab.pcap", ROOT / "samples" / "ot-lab.pcap"]


def best(fn, repeat: int) -> float:
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return min(times)


def bench(path: Path, repeat: int) -> dict:
    with PcapReader(str(path)) as r:
        packets = list(r)
    records = [parse_packet(p) for p in packets]
    n = len(packets)
    ot = "ot-lab" in path.name
    config = load_config(ROOT / "lab" / "ot" / "monitor.yaml") if ot and (ROOT / "lab" / "ot" / "monitor.yaml").exists() \
        else load_config()

    def read():
        with PcapReader(str(path)) as r:
            for _ in r:
                pass

    def parse():
        for p in packets:
            parse_packet(p)

    def detect():
        mon = Monitor(config)
        for rec in records:
            mon.process(rec)
        mon.close()

    def store():
        with tempfile.TemporaryDirectory() as tmp:
            mon = Monitor(config, Storage(Path(tmp) / "b.db", tmp))
            for rec in records:
                mon.process(rec)
            mon.close()

    def end2end():
        with tempfile.TemporaryDirectory() as tmp:
            mon = Monitor(config, Storage(Path(tmp) / "b.db", tmp))
            with PcapReader(str(path)) as r:
                for p in r:
                    mon.process(parse_packet(p))
            mon.close()

    result = {"capture": path.name, "packets": n}
    for name, fn in (("read", read), ("parse", parse), ("detect", detect), ("store", store), ("end2end", end2end)):
        seconds = best(fn, repeat)
        result[name] = {"seconds": round(seconds, 3), "packets_per_s": round(n / seconds)}
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repeat", type=int, default=3, help="runs per stage; the fastest counts (default 3)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    env = {"python": platform.python_version(), "scapy": scapy_version, "machine": platform.machine(),
           "system": f"{platform.system()} {platform.release()}", "processor": platform.processor()}
    results = [bench(p, args.repeat) for p in CAPTURES if p.exists()]
    if args.json:
        print(json.dumps({"environment": env, "results": results}, indent=2))
        return 0
    print(f"Python {env['python']}, scapy {env['scapy']}, {env['system']} ({env['machine']}); "
          f"best of {args.repeat}\n")
    print("| Capture | Packets | Read (scapy) | Parse | Detect | Detect + store | End to end |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for r in results:
        cells = " | ".join(f"{r[s]['packets_per_s']:,} pkt/s" for s in ("read", "parse", "detect", "store", "end2end"))
        print(f"| {r['capture']} | {r['packets']:,} | {cells} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
