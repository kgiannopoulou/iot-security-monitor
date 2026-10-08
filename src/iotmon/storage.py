"""Persistence: SQLite (queried by the dashboard), JSONL alerts (for SIEM
ingestion) and an optional CSV packet log (for spreadsheets / grep).

The database is the monitor's log: alerts, devices, flows, per-minute
traffic, the MQTT view, and one row per monitoring run. Alerts carry a
triage status (open / acknowledged / resolved / false_positive) that an
analyst changes from the CLI or the dashboard (Week 5)."""

from __future__ import annotations

import csv
import json
import sqlite3
import time
from pathlib import Path

from . import __version__
from .flows import Flow
from .inventory import Device
from .mqtt import MqttTracker
from .models import Alert, PacketRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    rule      TEXT NOT NULL,
    rule_id   TEXT,
    severity  TEXT NOT NULL,
    title     TEXT NOT NULL,
    src       TEXT,
    dst       TEXT,
    mitre     TEXT,
    details   TEXT,
    run_id    INTEGER,
    status    TEXT NOT NULL DEFAULT 'open',
    note      TEXT,
    updated   REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS devices (
    key          TEXT PRIMARY KEY,
    mac          TEXT,
    ips          TEXT,
    vendor       TEXT,
    name         TEXT,
    role         TEXT,
    first_seen   REAL,
    last_seen    REAL,
    packets_sent INTEGER,
    packets_recv INTEGER,
    bytes_sent   INTEGER,
    bytes_recv   INTEGER,
    protocols    TEXT,
    services     TEXT,
    peers        INTEGER,
    connections  INTEGER,
    status       TEXT
);

CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol    TEXT,
    client_ip   TEXT,
    client_port INTEGER,
    server_ip   TEXT,
    server_port INTEGER,
    app         TEXT,
    first_seen  REAL,
    last_seen   REAL,
    duration    REAL,
    packets     INTEGER,
    bytes       INTEGER,
    packets_c2s INTEGER,
    packets_s2c INTEGER,
    state       TEXT
);

-- MQTT view (Week 4): one row per client and per topic, replaced on each commit.
CREATE TABLE IF NOT EXISTS mqtt_clients (
    key           TEXT PRIMARY KEY,
    client_id     TEXT,
    ip            TEXT,
    broker        TEXT,
    username      TEXT,
    first_seen    REAL,
    last_seen     REAL,
    connects      INTEGER,
    refused       INTEGER,
    messages      INTEGER,
    topics        TEXT,
    subscriptions TEXT
);

CREATE TABLE IF NOT EXISTS mqtt_topics (
    topic       TEXT PRIMARY KEY,
    first_seen  REAL,
    last_seen   REAL,
    messages    INTEGER,
    last_value  TEXT,
    publishers  TEXT
);

-- Per-minute traffic volume by application protocol, for dashboard charts.
CREATE TABLE IF NOT EXISTS traffic (
    minute  INTEGER NOT NULL,
    app     TEXT NOT NULL,
    packets INTEGER NOT NULL,
    bytes   INTEGER NOT NULL,
    PRIMARY KEY (minute, app)
);

-- One row per monitoring run (Week 5): what was analysed, when, and how much.
-- started / updated / ended are wall-clock times, first / last_packet packet times.
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mode         TEXT,
    source       TEXT,
    version      TEXT,
    started      REAL,
    updated      REAL,
    ended        REAL,
    first_packet REAL,
    last_packet  REAL,
    packets      INTEGER NOT NULL DEFAULT 0,
    alerts       INTEGER NOT NULL DEFAULT 0
);
"""

# Bumped whenever a table or column is added; `iotmon db info` shows it.
SCHEMA_VERSION = 5

# Columns added after a table was first released. Databases written by an
# older version are upgraded in place when they are opened.
ADDED_COLUMNS = {
    "devices": (("connections", "INTEGER"), ("status", "TEXT")),                    # Week 2
    "alerts": (("rule_id", "TEXT"),                                                 # Week 3
               ("run_id", "INTEGER"), ("status", "TEXT NOT NULL DEFAULT 'open'"),   # Week 5
               ("note", "TEXT"), ("updated", "REAL")),
}

ALERT_STATUSES = ("open", "acknowledged", "resolved", "false_positive")
ACTIVE_STATUSES = ("open", "acknowledged")  # still needs someone's attention

CSV_FIELDS = ["time", "src_mac", "dst_mac", "src_ip", "dst_ip", "protocol",
              "sport", "dport", "port", "tcp_flags", "app", "length", "info"]


def open_db(db_path: str | Path) -> sqlite3.Connection:
    """Open the monitor database for writing, creating or upgrading it."""
    db = sqlite3.connect(db_path, timeout=10)  # the monitor and the dashboard can both write
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")  # readers never block the writer
    db.executescript(SCHEMA)
    for table, columns in ADDED_COLUMNS.items():
        have = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for col, kind in columns:
            if col not in have:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {kind}")
    db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, severity)")
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    db.commit()
    return db


def set_alert_status(db_path: str | Path, ids: list[int], status: str, note: str | None = None,
                     now: float | None = None) -> list[int]:
    """Triage alerts and return the IDs that exist. A note replaces the previous one."""
    if status not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {', '.join(ALERT_STATUSES)}")
    if not ids:
        return []
    db = open_db(db_path)
    try:
        found = [r[0] for r in db.execute(f"SELECT id FROM alerts WHERE id IN ({','.join('?' * len(ids))})",
                                          ids)]
        now = time.time() if now is None else now
        for i in found:
            if note is None:
                db.execute("UPDATE alerts SET status = ?, updated = ? WHERE id = ?", (status, now, i))
            else:
                db.execute("UPDATE alerts SET status = ?, note = ?, updated = ? WHERE id = ?",
                           (status, note, now, i))
        db.commit()
        return found
    finally:
        db.close()


def prune(db_path: str | Path, before: float) -> dict[str, int]:
    """Retention: delete alerts, flows and traffic older than `before` (packet time).

    Devices, MQTT clients/topics and runs are kept. They are the inventory
    and the audit trail, and they stay small.
    """
    db = open_db(db_path)
    try:
        deleted = {
            "alerts": db.execute("DELETE FROM alerts WHERE ts < ?", (before,)).rowcount,
            "flows": db.execute("DELETE FROM flows WHERE last_seen < ?", (before,)).rowcount,
            "traffic": db.execute("DELETE FROM traffic WHERE minute + 60 <= ?", (before,)).rowcount,
        }
        db.commit()
        db.execute("VACUUM")
        return deleted
    finally:
        db.close()


class Storage:
    def __init__(self, db_path: str | Path, out_dir: str | Path | None = None,
                 packet_csv: bool = False, reset: bool = False, mode: str = "read", source: str | None = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if reset:
            for suffix in ("", "-wal", "-shm"):
                Path(f"{self.db_path}{suffix}").unlink(missing_ok=True)
        self.db = open_db(self.db_path)
        now = time.time()
        self.run_id = self.db.execute(
            "INSERT INTO runs (mode, source, version, started, updated) VALUES (?,?,?,?,?)",
            (mode, source, __version__, now, now)).lastrowid
        self.db.commit()
        self._run = {"packets": 0, "alerts": 0, "first_packet": None, "last_packet": None}

        self.out_dir = Path(out_dir) if out_dir else self.db_path.parent
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._alerts_jsonl = open(self.out_dir / "alerts.jsonl", "w" if reset else "a", encoding="utf-8")
        self._csv_file = None
        if packet_csv:
            self._csv_file = open(self.out_dir / "packets.csv", "w", newline="", encoding="utf-8")
            self._csv = csv.DictWriter(self._csv_file, fieldnames=CSV_FIELDS, extrasaction="ignore")
            self._csv.writeheader()
        self._traffic: dict[tuple[int, str], list[int]] = {}

    # -- writes ------------------------------------------------------------ #
    def packet(self, rec: PacketRecord) -> None:
        run = self._run
        run["packets"] += 1
        if run["first_packet"] is None:
            run["first_packet"] = rec.ts
        run["last_packet"] = rec.ts
        key = (int(rec.ts // 60) * 60, rec.app or rec.protocol)
        t = self._traffic.setdefault(key, [0, 0])
        t[0] += 1
        t[1] += rec.length
        if self._csv_file:
            self._csv.writerow(rec.as_row())

    def alert(self, alert: Alert) -> None:
        self.db.execute(
            "INSERT INTO alerts (ts, rule, rule_id, severity, title, src, dst, mitre, details, run_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (alert.ts, alert.rule, alert.rule_id, alert.severity, alert.title, alert.src, alert.dst,
             alert.mitre, json.dumps(alert.details), self.run_id),
        )
        self._run["alerts"] += 1
        self._alerts_jsonl.write(json.dumps(alert.as_dict()) + "\n")
        self._alerts_jsonl.flush()

    def flows(self, flows: list[Flow]) -> None:
        self.db.executemany(
            "INSERT INTO flows (protocol, client_ip, client_port, server_ip, server_port, app, first_seen,"
            " last_seen, duration, packets, bytes, packets_c2s, packets_s2c, state)"
            " VALUES (:protocol,:client_ip,:client_port,:server_ip,:server_port,:app,:first_seen,"
            ":last_seen,:duration,:packets,:bytes,:packets_c2s,:packets_s2c,:state)",
            [f.as_dict() for f in flows],
        )

    def devices(self, devices: list[Device]) -> None:
        rows = []
        for d in devices:
            r = d.as_dict()
            r["ips"] = ",".join(r["ips"])
            r["protocols"] = ",".join(r["protocols"])
            r["services"] = ",".join(str(p) for p in r["services"])
            rows.append(r)
        self.db.executemany(
            "INSERT OR REPLACE INTO devices (key, mac, ips, vendor, name, role, first_seen, last_seen,"
            " packets_sent, packets_recv, bytes_sent, bytes_recv, protocols, services, peers, connections, status)"
            " VALUES (:key,:mac,:ips,:vendor,:name,:role,:first_seen,:last_seen,:packets_sent,:packets_recv,"
            ":bytes_sent,:bytes_recv,:protocols,:services,:peers,:connections,:status)",
            rows,
        )

    def mqtt(self, tracker: MqttTracker) -> None:
        self.db.executemany(
            "INSERT OR REPLACE INTO mqtt_clients (key, client_id, ip, broker, username, first_seen, last_seen,"
            " connects, refused, messages, topics, subscriptions) VALUES (:key,:client_id,:ip,:broker,:username,"
            ":first_seen,:last_seen,:connects,:refused,:messages,:topics,:subscriptions)",
            [c.as_dict() for c in tracker.clients.values()],
        )
        self.db.executemany(
            "INSERT OR REPLACE INTO mqtt_topics (topic, first_seen, last_seen, messages, last_value, publishers)"
            " VALUES (:topic,:first_seen,:last_seen,:messages,:last_value,:publishers)",
            [t.as_dict() for t in tracker.topics.values()],
        )

    def commit(self, ended: bool = False) -> None:
        now = time.time()
        self.db.execute(
            "UPDATE runs SET updated = :now, ended = :ended, first_packet = :first_packet,"
            " last_packet = :last_packet, packets = :packets, alerts = :alerts WHERE id = :id",
            {**self._run, "now": now, "ended": now if ended else None, "id": self.run_id})
        for (minute, app), (pkts, nbytes) in self._traffic.items():
            self.db.execute(
                "INSERT INTO traffic (minute, app, packets, bytes) VALUES (?,?,?,?)"
                " ON CONFLICT(minute, app) DO UPDATE SET packets = packets + excluded.packets,"
                " bytes = bytes + excluded.bytes",
                (minute, app, pkts, nbytes),
            )
        self._traffic.clear()
        self.db.commit()
        if self._csv_file:
            self._csv_file.flush()

    def close(self) -> None:
        self.commit(ended=True)
        self.db.close()
        self._alerts_jsonl.close()
        if self._csv_file:
            self._csv_file.close()
