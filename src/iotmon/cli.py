"""Command line interface.

    python -m iotmon read samples/iot-lab.pcap        # replay a capture
    python -m iotmon live -i iotlab0                  # watch an interface
    python -m iotmon report                           # summarise the database
    python -m iotmon dashboard                        # web dashboard
    python -m iotmon inventory learn baseline.pcap    # build the asset register
    python -m iotmon inventory show                   # list known assets
    python -m iotmon baseline learn baseline.pcap     # learn normal behaviour per device
    python -m iotmon baseline show                    # what each device normally does
    python -m iotmon mqtt                             # MQTT clients and topics from the database
    python -m iotmon status                           # security posture at a glance
    python -m iotmon alerts --severity high           # query the alert log
    python -m iotmon alerts ack 3 4 --note "..."      # triage alerts
    python -m iotmon alerts export -o alerts.csv      # export for a report or a SIEM
    python -m iotmon db info                          # schema, row counts, monitoring runs
    python -m iotmon rules -v                         # detection rules and their thresholds
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .assets import DEFAULT_REGISTER, AssetRegister
from .baseline import DEFAULT_BASELINE, Baseline
from .config import load_config
from .models import register_rules
from .display import Printer
from .pipeline import Monitor
from .storage import ALERT_STATUSES, SCHEMA_VERSION, Storage, prune, set_alert_status

DEFAULT_DB = "data/iotmon.db"


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="site config (YAML) merged over config.yaml")
    p.add_argument("--rules", help="detection rule file (default rules/detection_rules.yaml)")
    p.add_argument("--speed", type=float, metavar="X",
                   help="read: replay the capture in real time, X times faster (for demos)")
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


def _config(args) -> dict:
    config = load_config(args.config, getattr(args, "rules", None))
    if getattr(args, "rules", None):
        register_rules(config["rules"])
    return config


def _build_monitor(args, mode: str, source: str | None) -> Monitor:
    config = _config(args)
    storage = None
    if not args.no_store:
        storage = Storage(args.db, args.out_dir, packet_csv=args.csv, reset=not args.append,
                          mode=mode, source=source)
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

    mon = _build_monitor(args, "read", Path(args.pcap).as_posix())
    records = read_pcap(args.pcap, limit=args.count)
    if args.speed:
        records = _paced(records, args.speed)
    mon.run(records)
    _summary(mon)
    return 0


def cmd_live(args) -> int:
    from .capture import sniff_live

    mon = _build_monitor(args, "live", args.interface or "default interface")
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


def _paced(records, speed: float):
    """Yield records at their capture pace divided by `speed` (wall clock)."""
    t0 = c0 = None
    for rec in records:
        if t0 is None:
            t0, c0 = rec.ts, time.monotonic()
        delay = (rec.ts - t0) / speed - (time.monotonic() - c0)
        if delay > 0:
            time.sleep(delay)
        yield rec


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

    _print_mqtt(db, indent="  ", heading="\nMQTT CLIENTS")

    print("\nALERTS")
    rows = db.execute("SELECT * FROM alerts ORDER BY ts").fetchall()
    for a in rows:
        print(f"  {t(a['ts'])}  {a['severity'].upper():<8} {a['rule_id'] or '':<8} {a['rule']:<19} {a['title']}")
    if not rows:
        print("  none")
    return 0


def _print_mqtt(db, indent: str = "", heading: str = "MQTT CLIENTS") -> bool:
    try:
        clients = db.execute("SELECT * FROM mqtt_clients ORDER BY broker, ip, key").fetchall()
        topics = db.execute("SELECT * FROM mqtt_topics ORDER BY topic").fetchall()
    except sqlite3.OperationalError:  # database from before Week 4
        return False
    if not clients:
        return False
    print(heading)
    print(f"{indent}{'CLIENT ID':<30} {'HOST':<15} {'BROKER':<15} {'CONN':>4} {'REFUSED':>7} {'MSGS':>6}  PUBLISHES TO / SUBSCRIBED TO")
    for c in clients:
        pubs = c["topics"].replace(",", ", ") or "-"
        subs = c["subscriptions"].replace(",", ", ")
        print(f"{indent}{(c['client_id'] or c['key'])[:30]:<30} {c['ip']:<15} {c['broker']:<15} {c['connects']:>4} "
              f"{c['refused']:>7} {c['messages']:>6}  {pubs}" + (f"  [sub: {subs}]" if subs else ""))
    print(f"\n{indent}{'TOPIC':<32} {'MESSAGES':>8}  {'LAST VALUE':<24} PUBLISHERS")
    for t in topics:
        print(f"{indent}{t['topic'][:32]:<32} {t['messages']:>8}  {t['last_value'][:24]:<24} "
              f"{t['publishers'].replace(',', ', ')}")
    return True


def cmd_mqtt(args) -> int:
    if not Path(args.db).exists():
        print(f"error: no database at {args.db} - run 'read' or 'live' first", file=sys.stderr)
        return 1
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row
    if not _print_mqtt(db):
        print("no MQTT traffic in this database", file=sys.stderr)
        return 1
    return 0


def _need_db(path: str) -> bool:
    if Path(path).exists():
        return True
    print(f"error: no database at {path} - run 'read' or 'live' first", file=sys.stderr)
    return False


def _can_print(text: str) -> bool:
    try:
        text.encode(sys.stdout.encoding or "ascii")
        return True
    except UnicodeEncodeError:  # e.g. a cp1252 Windows console
        return False


def cmd_status(args) -> int:
    from .state import render_text, security_state

    if not _need_db(args.db):
        return 1
    colour = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    width = args.width or min(120, max(78, shutil.get_terminal_size((100, 24)).columns - 1))
    try:
        while True:
            state = security_state(args.db, recent=args.recent)
            if args.json:
                print(json.dumps(state, indent=2, default=str))
                return 0
            text = render_text(state, utc=args.utc, colour=colour, width=width, ascii=not _can_print("─"))
            if not args.watch:
                print(text)
                return 0
            print("\033[2J\033[H" + text + f"\n\nrefreshing every {args.watch:g} s - Ctrl+C to stop", flush=True)
            time.sleep(args.watch)
    except KeyboardInterrupt:
        return 0


def _since(value: str | None) -> float | None:
    """'15m', '2h', '7d' before now, or an ISO date/time."""
    if not value:
        return None
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if value[-1] in units and value[:-1].replace(".", "", 1).isdigit():
        return time.time() - float(value[:-1]) * units[value[-1]]
    dt = datetime.fromisoformat(value)
    return (dt if dt.tzinfo else dt.astimezone()).timestamp()


def _filtered_alerts(args, limit: int) -> list[dict]:
    from .state import connect_ro, query_alerts

    con = connect_ro(args.db)
    try:
        return query_alerts(con, args.severity, args.status, args.rule, args.ip, _since(args.since), limit)
    finally:
        con.close()


def cmd_alerts_list(args) -> int:
    if not _need_db(args.db):
        return 1
    rows = _filtered_alerts(args, args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    tz = timezone.utc if args.utc else None
    print(f"{'ID':>4}  {'TIME':<19}  {'SEVERITY':<8} {'RULE':<8} {'STATUS':<14} ALERT")
    for a in reversed(rows):  # oldest first reads like a timeline
        when = datetime.fromtimestamp(a["ts"], tz=tz).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{a['id']:>4}  {when}  {a['severity'].upper():<8} {a['rule_id'] or '':<8} {a['status']:<14} "
              f"{a['title']}" + (f"\n{'':<59}note: {a['note']}" if a.get("note") else ""))
    print(f"\n{len(rows)} alert{'s' if len(rows) != 1 else ''}", file=sys.stderr)
    return 0


def cmd_alerts_triage(args) -> int:
    if not _need_db(args.db):
        return 1
    found = set(set_alert_status(args.db, args.ids, args.new_status, args.note))
    for i in args.ids:
        if i in found:
            print(f"alert {i}: {args.new_status}" + (f" ({args.note})" if args.note else ""))
        else:
            print(f"error: no alert {i}", file=sys.stderr)
    return 0 if len(found) == len(set(args.ids)) else 1


def cmd_alerts_export(args) -> int:
    from .state import export_rows, write_csv

    if not _need_db(args.db):
        return 1
    alerts = _filtered_alerts(args, limit=10**9)
    out = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump([{**r, "details": json.loads(r["details"])} for r in export_rows(alerts)], out, indent=2)
            out.write("\n")
        else:
            write_csv(alerts, out)
    finally:
        if args.output:
            out.close()
            print(f"{len(alerts)} alerts -> {args.output}", file=sys.stderr)
    return 0


def cmd_db_info(args) -> int:
    if not _need_db(args.db):
        return 1
    db = sqlite3.connect(f"file:{Path(args.db).as_posix()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    version = db.execute("PRAGMA user_version").fetchone()[0]
    size = sum(Path(f"{args.db}{s}").stat().st_size for s in ("", "-wal") if Path(f"{args.db}{s}").exists())
    print(f"database   {Path(args.db).as_posix()} ({size / 1024:.0f} KiB)")
    print(f"schema     version {version}" + ("" if version >= SCHEMA_VERSION else
                                             f" (upgraded to {SCHEMA_VERSION} on the next write)"))
    tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'"
                                       " AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    print(f"\n{'TABLE':<14} {'ROWS':>6}")
    for t in tables:
        print(f"{t:<14} {db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]:>6}")
    if "runs" in tables:
        tz = timezone.utc if args.utc else None
        print(f"\n{'RUN':>4}  {'MODE':<5} {'STARTED':<19}  {'DURATION':>8}  {'PACKETS':>8} {'ALERTS':>6}  SOURCE")
        unfinished = False
        for r in db.execute("SELECT * FROM runs ORDER BY id"):
            unfinished |= r["ended"] is None
            started = datetime.fromtimestamp(r["started"], tz=tz).strftime("%Y-%m-%d %H:%M:%S")
            dur = f"{(r['ended'] or r['updated']) - r['started']:.0f} s" + ("" if r["ended"] else "*")
            print(f"{r['id']:>4}  {r['mode']:<5} {started}  {dur:>8}  {r['packets']:>8} {r['alerts']:>6}  "
                  f"{r['source'] or ''}")
        if unfinished:
            print("(* still running, or stopped without a clean shutdown)")
    db.close()
    return 0


def cmd_db_prune(args) -> int:
    if not _need_db(args.db):
        return 1
    if args.before:
        before = _since(args.before)
    else:
        # Packet time, not wall-clock time: replayed captures keep their own dates.
        con = sqlite3.connect(args.db)
        last = con.execute("SELECT MAX(minute) FROM traffic").fetchone()[0]
        con.close()
        if last is None:
            print("nothing to prune", file=sys.stderr)
            return 0
        before = last + 60 - timedelta(days=args.keep_days).total_seconds()
    deleted = prune(args.db, before)
    cutoff = datetime.fromtimestamp(before, tz=timezone.utc).isoformat(timespec="seconds")
    print(f"deleted everything before {cutoff}: " + ", ".join(f"{n} {t}" for t, n in deleted.items()))
    return 0


def cmd_inventory_learn(args) -> int:
    """Build the asset register from traffic you trust (every device is approved)."""
    from .capture import read_pcap

    records = read_pcap(args.pcap)
    if args.duration is not None:
        records = _first_seconds(records, args.duration)
    assets = AssetRegister(args.inventory)
    mon = Monitor(_config(args), assets=assets, new_asset_status="approved")
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

    config = _config(args)
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


def cmd_rules(args) -> int:
    config = _config(args)
    if args.json:
        print(json.dumps(config["rules"], indent=2))
        return 0
    print(f"{'ID':<8} {'DETECTOR':<20} {'ON':<3} {'SEVERITIES':<22} NAME")
    for r in config["rules"]:
        on = "yes" if config["detections"][r["detector"]].get("enabled", True) else "no"
        print(f"{r['id']:<8} {r['detector']:<20} {on:<3} {', '.join(r['severities']):<22} {r['name']}")
        if args.verbose:
            settings = config["detections"][r["detector"]]
            for k, v in settings.items():
                if k != "enabled":
                    print(f"{'':<12}{k} = {v}")
            print(f"{'':<12}ATT&CK: {'; '.join(r['attack'])}")
    return 0


def cmd_dashboard(args) -> int:
    from .dashboard.app import create_app

    app = create_app(args.db, read_only=args.read_only)
    print(f"dashboard on http://{args.host}:{args.port}  (db: {args.db}"
          f"{', read-only' if args.read_only else ''})", file=sys.stderr)
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

    p = sub.add_parser("mqtt", help="print MQTT clients and topics from the database")
    p.add_argument("--db", default=DEFAULT_DB)
    p.set_defaults(func=cmd_mqtt)

    p = sub.add_parser("status", help="security posture: headline numbers, why, affected devices, recent alerts")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--utc", action="store_true")
    p.add_argument("-w", "--watch", type=float, metavar="SECONDS", help="redraw every N seconds")
    p.add_argument("-n", "--recent", type=int, default=10, help="recent alerts to show (default 10)")
    p.add_argument("--json", action="store_true", help="print the full state as JSON")
    p.add_argument("--width", type=int, help="line width (default: the terminal's, 78-120)")
    p.set_defaults(func=cmd_status)

    filters = argparse.ArgumentParser(add_help=False)
    filters.add_argument("--db", default=DEFAULT_DB)
    filters.add_argument("--severity", choices=("low", "medium", "high", "critical"))
    filters.add_argument("--status", choices=(*ALERT_STATUSES, "active"),
                         help="triage status; 'active' = open or acknowledged")
    filters.add_argument("--rule", help="rule ID or name, e.g. DET-002 or port_scan")
    filters.add_argument("--ip", help="alerts where this address is the source or destination")
    filters.add_argument("--since", help="e.g. 30m, 6h, 7d, or an ISO date/time")
    listing = argparse.ArgumentParser(add_help=False)
    listing.add_argument("--limit", type=int, default=200)
    listing.add_argument("--json", action="store_true")
    listing.add_argument("--utc", action="store_true")
    p = sub.add_parser("alerts", parents=[filters, listing],
                       help="query, triage and export the alert log (default action: list)")
    p.set_defaults(func=cmd_alerts_list)
    al = p.add_subparsers(dest="action")
    q = al.add_parser("list", parents=[filters, listing], help="list alerts (the default)")
    q.set_defaults(func=cmd_alerts_list)
    for name, status, text in (("ack", "acknowledged", "someone is investigating"),
                               ("resolve", "resolved", "handled, stops counting towards the posture"),
                               ("fp", "false_positive", "not a real problem, stops counting"),
                               ("reopen", "open", "back to open")):
        q = al.add_parser(name, help=f"mark alerts {status} ({text})")
        q.add_argument("ids", nargs="+", type=int, metavar="ID")
        q.add_argument("--note", help="analyst note stored with the alert")
        q.add_argument("--db", default=DEFAULT_DB)
        q.set_defaults(func=cmd_alerts_triage, new_status=status)
    q = al.add_parser("export", parents=[filters], help="export alerts to CSV or JSON (oldest first)")
    q.add_argument("-o", "--output", help="file to write (default stdout)")
    q.add_argument("--format", choices=("csv", "json"), default="csv")
    q.set_defaults(func=cmd_alerts_export)

    p = sub.add_parser("db", help="database information and retention")
    dbp = p.add_subparsers(dest="action", required=True)
    q = dbp.add_parser("info", help="schema version, rows per table, monitoring runs")
    q.add_argument("--utc", action="store_true")
    q.set_defaults(func=cmd_db_info)
    q = dbp.add_parser("prune", help="delete alerts, flows and traffic older than a cut-off")
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--keep-days", type=float, help="keep the last N days (packet time)")
    g.add_argument("--before", help="delete before this time (e.g. 2026-10-01 or 30d)")
    q.set_defaults(func=cmd_db_prune)
    for q in dbp.choices.values():
        q.add_argument("--db", default=DEFAULT_DB)

    p = sub.add_parser("inventory", help="manage the asset register (known devices)")
    inv = p.add_subparsers(dest="action", required=True)
    q = inv.add_parser("learn", help="build the register from a capture of trusted traffic")
    q.add_argument("pcap")
    q.add_argument("-d", "--duration", type=float, help="only use the first N seconds of the capture")
    q.add_argument("--config", help="site config (YAML) merged over config.yaml")
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
    q.add_argument("--config", help="site config (YAML) merged over config.yaml")
    q.add_argument("--force", action="store_true", help="replace an existing baseline file")
    q.set_defaults(func=cmd_baseline_learn)
    q = bl.add_parser("show", help="print the learned device profiles")
    q.add_argument("--json", action="store_true", help="print the raw JSON file")
    q.set_defaults(func=cmd_baseline_show)
    for q in bl.choices.values():
        q.add_argument("--baseline", default=DEFAULT_BASELINE, metavar="JSON",
                       help=f"baseline file (default {DEFAULT_BASELINE})")

    p = sub.add_parser("rules", help="list the detection rules (rules/detection_rules.yaml)")
    p.add_argument("--config", help="site config (YAML) merged over config.yaml")
    p.add_argument("--rules", help="detection rule file (default rules/detection_rules.yaml)")
    p.add_argument("-v", "--verbose", action="store_true", help="also print thresholds and ATT&CK techniques")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("dashboard", help="serve the web dashboard")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--read-only", action="store_true", help="disable alert triage from the web page")
    p.set_defaults(func=cmd_dashboard)

    args = parser.parse_args(argv)
    return args.func(args)
