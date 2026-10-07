"""Command line interface.

    python -m iotmon read samples/iot-lab.pcap        # replay a capture
    python -m iotmon live -i iotlab0                  # watch an interface
    python -m iotmon report                           # summarise the database
    python -m iotmon dashboard                        # web dashboard
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import load_config
from .display import Printer
from .pipeline import Monitor
from .storage import Storage

DEFAULT_DB = "data/iotmon.db"


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="TOML file overriding the defaults")
    p.add_argument("--db", default=DEFAULT_DB, help=f"SQLite database (default {DEFAULT_DB})")
    p.add_argument("--out-dir", help="where alerts.jsonl / packets.csv go (default: next to the db)")
    p.add_argument("--csv", action="store_true", help="also write every packet to packets.csv")
    p.add_argument("--append", action="store_true", help="keep existing database contents")
    p.add_argument("--no-store", action="store_true", help="do not write any output files")
    p.add_argument("-q", "--quiet", action="store_true", help="print alerts only, not every packet")
    p.add_argument("--utc", action="store_true", help="print times in UTC instead of local time")
    p.add_argument("-c", "--count", type=int, help="stop after N packets")


def _build_monitor(args) -> Monitor:
    config = load_config(args.config)
    storage = None
    if not args.no_store:
        storage = Storage(args.db, args.out_dir, packet_csv=args.csv, reset=not args.append)
    printer = Printer(show_packets=not args.quiet, utc=args.utc)
    return Monitor(config, storage, printer)


def _summary(mon: Monitor) -> None:
    print(f"\n{mon.packets} packets, {len(mon.inventory.devices)} devices, {len(mon.alerts)} alerts",
          file=sys.stderr)
    if mon.alerts:
        by_sev = Counter(a.severity for a in mon.alerts)
        print("alerts by severity: " + ", ".join(f"{k}={v}" for k, v in by_sev.most_common()), file=sys.stderr)


def cmd_read(args) -> int:
    from .capture import read_pcap

    mon = _build_monitor(args)
    mon.run(read_pcap(args.pcap, limit=args.count))
    _summary(mon)
    return 0


def cmd_live(args) -> int:
    from .capture import sniff_live

    mon = _build_monitor(args)
    print(f"capturing on {args.interface or 'default interface'}"
          f"{' filter ' + repr(args.bpf) if args.bpf else ''} - Ctrl+C to stop", file=sys.stderr)
    try:
        mon.run(sniff_live(args.interface, bpf=args.bpf, limit=args.count, timeout=args.timeout))
    except PermissionError:
        print("error: live capture needs root / CAP_NET_RAW (or Npcap + admin on Windows)", file=sys.stderr)
        return 1
    _summary(mon)
    return 0


def cmd_report(args) -> int:
    if not Path(args.db).exists():
        print(f"error: no database at {args.db} - run 'read' or 'live' first", file=sys.stderr)
        return 1
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row
    tz = timezone.utc if args.utc else None

    def t(ts):
        return datetime.fromtimestamp(ts, tz=tz).strftime("%Y-%m-%d %H:%M:%S")

    print("DEVICES")
    print(f"  {'IP':<15} {'MAC':<17} {'VENDOR':<28} {'ROLE':<30} {'SERVICES':<12} NAME")
    for d in db.execute("SELECT * FROM devices ORDER BY first_seen"):
        print(f"  {d['ips']:<15} {d['mac'] or '-':<17} {d['vendor'][:28]:<28} {d['role'][:30]:<30} "
              f"{d['services'] or '-':<12} {d['name'] or ''}")

    print("\nTOP FLOWS (by bytes)")
    for f in db.execute("SELECT * FROM flows ORDER BY bytes DESC LIMIT 10"):
        print(f"  {f['client_ip']:>15}:{f['client_port'] or '':<5} -> {f['server_ip']}:{f['server_port'] or ''}"
              f"  {f['protocol']}/{f['app'] or '?':<8} {f['packets']:>6} pkts {f['bytes']:>9} B  {f['state']}")

    print("\nALERTS")
    rows = db.execute("SELECT * FROM alerts ORDER BY ts").fetchall()
    for a in rows:
        print(f"  {t(a['ts'])}  {a['severity'].upper():<8} {a['rule']:<18} {a['title']}")
    if not rows:
        print("  none")
    return 0


def cmd_dashboard(args) -> int:
    from .dashboard.app import create_app

    app = create_app(args.db)
    print(f"dashboard on http://{args.host}:{args.port}  (db: {args.db})", file=sys.stderr)
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iotmon", description="IoT Security Monitoring System")
    parser.add_argument("--version", action="version", version=f"iotmon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("read", help="analyse a pcap / pcapng file")
    p.add_argument("pcap")
    _add_common(p)
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("live", help="capture from a network interface")
    p.add_argument("-i", "--interface", help="interface name, e.g. iotlab0 or eth0")
    p.add_argument("-f", "--bpf", help="BPF capture filter, e.g. 'not port 22'")
    p.add_argument("-t", "--timeout", type=float, help="stop after N seconds")
    _add_common(p)
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("report", help="print devices, top flows and alerts from the database")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--utc", action="store_true")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("dashboard", help="serve the web dashboard")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=cmd_dashboard)

    args = parser.parse_args(argv)
    return args.func(args)
