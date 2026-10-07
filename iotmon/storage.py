"""Persistence: SQLite (queried by the dashboard), JSONL alerts (for SIEM
ingestion) and an optional CSV packet log (for spreadsheets / grep)."""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from .flows import Flow
from .inventory import Device
from .models import Alert, PacketRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    rule      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    title     TEXT NOT NULL,
    src       TEXT,
    dst       TEXT,
    mitre     TEXT,
    details   TEXT
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
    peers        INTEGER
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

-- Per-minute traffic volume by application protocol, for dashboard charts.
CREATE TABLE IF NOT EXISTS traffic (
    minute  INTEGER NOT NULL,
    app     TEXT NOT NULL,
    packets INTEGER NOT NULL,
    bytes   INTEGER NOT NULL,
    PRIMARY KEY (minute, app)
);
"""

CSV_FIELDS = ["time", "src_mac", "dst_mac", "src_ip", "dst_ip", "protocol",
              "sport", "dport", "port", "tcp_flags", "app", "length", "info"]


class Storage:
    def __init__(self, db_path: str | Path, out_dir: str | Path | None = None,
                 packet_csv: bool = False, reset: bool = False):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if reset and self.db_path.exists():
            self.db_path.unlink()
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("PRAGMA journal_mode=WAL")  # dashboard reads while we write
        self.db.executescript(SCHEMA)

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
        key = (int(rec.ts // 60) * 60, rec.app or rec.protocol)
        t = self._traffic.setdefault(key, [0, 0])
        t[0] += 1
        t[1] += rec.length
        if self._csv_file:
            self._csv.writerow(rec.as_row())

    def alert(self, alert: Alert) -> None:
        self.db.execute(
            "INSERT INTO alerts (ts, rule, severity, title, src, dst, mitre, details) VALUES (?,?,?,?,?,?,?,?)",
            (alert.ts, alert.rule, alert.severity, alert.title, alert.src, alert.dst,
             alert.mitre, json.dumps(alert.details)),
        )
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
            "INSERT OR REPLACE INTO devices VALUES (:key,:mac,:ips,:vendor,:name,:role,:first_seen,:last_seen,"
            ":packets_sent,:packets_recv,:bytes_sent,:bytes_recv,:protocols,:services,:peers)",
            rows,
        )

    def commit(self) -> None:
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
        self.commit()
        self.db.close()
        self._alerts_jsonl.close()
        if self._csv_file:
            self._csv_file.close()
