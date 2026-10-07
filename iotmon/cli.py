"""Command line interface.

    python -m iotmon read samples/iot-lab.pcap        # replay a capture
    python -m iotmon live -i iotlab0                  # watch an interface
    python -m iotmon report                           # summarise the database
    python -m iotmon dashboard                        # web dashboard
    python -m iotmon inventory learn baseline.pcap    # build the asset register
    python -m iotmon inventory show                   # list known assets
    python -m iotmon baseline learn baseline.pcap     # learn normal behaviour per device
    python -m iotmon baseline show                    # what each device normally does
"""

from __future__ import annotations

import argparse
import json
import signal
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .assets import DEFAULT_REGISTER, AssetRegister
from .baseline import DEFAULT_BASELINE, Baseline
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
    p.add_argument("--inventory", metavar="JSON", nargs="?", const=DEFAULT_REGISTER,
                   help=f"use and update the asset register (default path {DEFAULT_REGISTER})")
    p.add_argument("--baseline", metavar="JSON", nargs="?", const=DEFAULT_BASELINE,
                   help="compare with a saved behavioural baseline; if the file does not exist yet, "
                        f"learn it during the learning period and save it (default path {DEFAULT_BASELINE})")


def _build_monitor(args) -> Monitor:
    config = load_config(args.config)
    storage = None
    if not args.no_store:
        storage = Storage(args.db, args.out_dir, packet_csv=args.csv, reset=not args.append)
    printer = Printer(show_packets=not args.quiet, utc=args.utc)
    assets = AssetRegister(args.inventory) if args.inventory else None
    baseline = _baseline(args.baseline, config) if args.baseline else None
    return Monitor(config, storage, printer, assets, baseline=baseline)


def _baseline(path: str, config: dict) -> Baseline:
    return Baseline(path, learning_period=float(config.get("baseline", {}).get("learning_period_s", 120)),
                    window=float(config["detections"].get("connection_rate", {}).get("window_s", 60)))


def _summary(mon: Monitor) -> None:
    print(f"\n{mon.packets} packets, {len(mon.inventory.devices)} devices, {len(mon.alerts)} alerts",
          file=sys.stderr)
    if mon.alerts:
        by_sev = Counter(a.severity for a in mon.alerts)
        print("alerts by severity: " + ", ".join(f"{k}={v}" for k, v in by_sev.most_common()), file=sys.stderr)
    if mon.assets is not None:
        added = Counter(mon.assets.get(k)["status"] for k in mon.added_assets)
        added_txt = ", ".join(f"{n} {status}" for status, n in sorted(added.items())) or "none"
        print(f"asset register {mon.assets.path.as_posix()}: {len(mon.assets)} assets, added: {added_txt}",
              file=sys.stderr)
    b = mon.baseline
    if b.path is not None:
        state = "compared with" if b.frozen else "learned and saved"
        print(f"baseline {b.path.as_posix()}: {state}, {len(b)} device profiles", file=sys.stderr)


def cmd_read(args) -> int:
    from .capture import read_pcap

    mon = _build_monitor(args)
    mon.run(read_pcap(args.pcap, limit=args.count))
    _summary(mon)
    return 0


def cmd_live(args) -> int:
    from .capture import sniff_live

    mon = _build_monitor(args)
    signal.signal(signal.SIGTERM, _stop)  # docker stop: shut down cleanly, flush outputs
    print(f"capturing on {args.interface or 'default interface'}"
          f"{' filter ' + repr(args.bpf) if args.bpf else ''} - Ctrl+C to stop", file=sys.stderr)
    try:
        mon.run(sniff_live(args.interface, bpf=args.bpf, limit=args.count, timeout=args.timeout))
    except PermissionError:
        print("error: live capture needs root / CAP_NET_RAW (or Npcap + admin on Windows)", file=sys.stderr)
        return 1
    _summary(mon)
    return 0


def _stop(signum, frame):
    raise KeyboardInterrupt


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
    print(f"  {'IP':<15} {'MAC':<17} {'VENDOR':<28} {'ROLE':<30} {'SERVICES':<12} {'CONN':>5}  NAME")
    for d in db.execute("SELECT * FROM devices ORDER BY first_seen"):
        print(f"  {d['ips']:<15} {d['mac'] or '-':<17} {d['vendor'][:28]:<28} {d['role'][:30]:<30} "
              f"{d['services'] or '-':<12} {d['connections'] or 0:>5}  {d['name'] or ''}")

    print("\nTOP FLOWS (by bytes)")
    for f in db.execute("SELECT * FROM flows ORDER BY bytes DESC LIMIT 10"):
        print(f"  {f['client_ip']:>15}:{f['client_port'] or '':<5} -> {f['server_ip']}:{f['server_port'] or ''}"
              f"  {f['protocol']}/{f['app'] or '?':<8} {f['packets']:>6} pkts {f['bytes']:>9} B  {f['state']}")

    print("\nALERTS")
    rows = db.execute("SELECT * FROM alerts ORDER BY ts").fetchall()
    for a in rows:
        print(f"  {t(a['ts'])}  {a['severity'].upper():<8} {a['rule_id'] or '':<8} {a['rule']:<19} {a['title']}")
    if not rows:
        print("  none")
    return 0


def cmd_inventory_learn(args) -> int:
    """Build the asset register from traffic you trust (every device is approved)."""
    from .capture import read_pcap

    records = read_pcap(args.pcap)
    if args.duration is not None:
        records = _first_seconds(records, args.duration)
    assets = AssetRegister(args.inventory)
    mon = Monitor(load_config(args.config), assets=assets, new_asset_status="approved")
    mon.run(records)
    print(f"learned {len(mon.inventory.devices)} devices from {mon.packets} packets; "
          f"{len(mon.added_assets)} new, register {assets.path.as_posix()} now holds {len(assets)} assets",
          file=sys.stderr)
    return 0


def _first_seconds(records, seconds: float):
    end = None
    for rec in records:
        if end is None:
            end = rec.ts + seconds
        if rec.ts >= end:
            return
        yield rec


def cmd_inventory_show(args) -> int:
    assets = AssetRegister(args.inventory)
    if not len(assets):
        print(f"asset register {args.inventory} is empty - run 'inventory learn' or 'read --inventory'",
              file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(assets.by_ip(), indent=2))
        return 0
    print(f"{'IP':<15} {'MAC':<17} {'VENDOR':<26} {'ROLE':<32} {'PROTOCOLS':<24} {'CONN':>5}  "
          f"{'FIRST SEEN (UTC)':<19}  {'LAST SEEN (UTC)':<19}  STATUS")
    for ip, a in assets.by_ip().items():
        protocols = ",".join(a["protocols"])
        print(f"{ip:<15} {a['mac'] or '-':<17} {a['vendor'][:26]:<26} {a['role'][:32]:<32} "
              f"{protocols[:24]:<24} {a['connections']:>5}  {_short(a['first_seen'])}  "
              f"{_short(a['last_seen'])}  {a['status']}")
    pending = sum(a["status"] == "pending" for a in assets.assets.values())
    print(f"\n{len(assets)} assets, {pending} pending review")
    return 0


def _short(iso: str) -> str:
    return iso[:19].replace("T", " ")


def cmd_inventory_approve(args) -> int:
    assets = AssetRegister(args.inventory)
    if args.all:
        targets = [k for k, a in assets.assets.items() if a["status"] == "pending"]
    else:
        targets = args.devices
    rc = 0
    for target in targets:
        key = assets.set_status(target, args.status)
        if key:
            print(f"{key}: {args.status}")
        else:
            print(f"error: {target} is not in {assets.path.as_posix()}", file=sys.stderr)
            rc = 1
    assets.save()
    return rc


def cmd_baseline_learn(args) -> int:
    """Learn normal behaviour from traffic you trust (the whole capture is the baseline)."""
    from .capture import read_pcap

    config = load_config(args.config)
    path = Path(args.baseline)
    if path.exists() and not args.force:
        print(f"error: {path.as_posix()} exists - pass --force to replace it", file=sys.stderr)
        return 1
    baseline = _baseline(None, config)
    baseline.path, baseline.learn_all = path, True
    records = read_pcap(args.pcap)
    if args.duration is not None:
        records = _first_seconds(records, args.duration)
    mon = Monitor(config, baseline=baseline)
    mon.run(records)
    print(f"learned {len(baseline)} device profiles from {mon.packets} packets -> {path.as_posix()}",
          file=sys.stderr)
    return 0


def cmd_baseline_show(args) -> int:
    baseline = Baseline(args.baseline)
    if not len(baseline):
        print(f"no baseline at {args.baseline} - run 'baseline learn' or 'read --baseline'", file=sys.stderr)
        return 1
    if args.json:
        print(Path(args.baseline).read_text(encoding="utf-8"), end="")
        return 0
    span = baseline.learned
    if span:
        print(f"learned from {span.get('packets', '?')} packets, {span.get('start', '?')} to {span.get('end', '?')}"
              f" (connection rate per {baseline.window:g}s)\n")
    print(f"{'IP':<15} {'USES PORTS':<24} {'SERVES PORTS':<16} {'PEAK CONN':>9}  INTERNET PEERS")
    for ip, prof in baseline.devices.items():
        uses = ",".join(map(str, sorted(prof.client_ports))) or "-"
        serves = ",".join(map(str, sorted(prof.server_ports))) or "-"
        peers = ", ".join(sorted(prof.external_peers)) or "none (local only)"
        print(f"{ip:<15} {uses[:24]:<24} {serves[:16]:<16} {prof.peak_connections:>9}  {peers}")
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

    p = sub.add_parser("inventory", help="manage the asset register (known devices)")
    inv = p.add_subparsers(dest="action", required=True)
    q = inv.add_parser("learn", help="build the register from a capture of trusted traffic")
    q.add_argument("pcap")
    q.add_argument("-d", "--duration", type=float, help="only use the first N seconds of the capture")
    q.add_argument("--config", help="TOML file overriding the defaults")
    q.set_defaults(func=cmd_inventory_learn)
    q = inv.add_parser("show", help="list the assets in the register")
    q.add_argument("--json", action="store_true", help="print the register keyed by IP address")
    q.set_defaults(func=cmd_inventory_show)
    q = inv.add_parser("approve", help="mark devices (MAC or IP) as approved")
    q.add_argument("devices", nargs="*", metavar="MAC_OR_IP")
    q.add_argument("--all", action="store_true", help="approve every pending device")
    q.add_argument("--status", default="approved", choices=("approved", "pending"))
    q.set_defaults(func=cmd_inventory_approve)
    for q in inv.choices.values():
        q.add_argument("--inventory", default=DEFAULT_REGISTER, metavar="JSON",
                       help=f"asset register file (default {DEFAULT_REGISTER})")

    p = sub.add_parser("baseline", help="manage the behavioural baseline (normal behaviour per device)")
    bl = p.add_subparsers(dest="action", required=True)
    q = bl.add_parser("learn", help="learn the baseline from a capture of trusted traffic")
    q.add_argument("pcap")
    q.add_argument("-d", "--duration", type=float, help="only use the first N seconds of the capture")
    q.add_argument("--config", help="TOML file overriding the defaults")
    q.add_argument("--force", action="store_true", help="replace an existing baseline file")
    q.set_defaults(func=cmd_baseline_learn)
    q = bl.add_parser("show", help="print the learned device profiles")
    q.add_argument("--json", action="store_true", help="print the raw JSON file")
    q.set_defaults(func=cmd_baseline_show)
    for q in bl.choices.values():
        q.add_argument("--baseline", default=DEFAULT_BASELINE, metavar="JSON",
                       help=f"baseline file (default {DEFAULT_BASELINE})")

    p = sub.add_parser("dashboard", help="serve the web dashboard")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=cmd_dashboard)

    args = parser.parse_args(argv)
    return args.func(args)
