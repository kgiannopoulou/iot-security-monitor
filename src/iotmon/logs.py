"""Structured logging: what the monitor itself is doing, one JSON object per
line (--log-format json), for the same log pipeline as everything else.

Alerts have their own outputs (terminal, SQLite, alerts.jsonl, SIEM); these
logs are the operational record around them: when a run started and
stopped, with what configuration, how fast it went, each alert as a log
event with its rule, severity and confidence, and errors.

    iotmon read samples/iot-lab.pcap -q --log-format json --log-file data/iotmon.log

Off unless --log-format or --log-file is given, so the terminal output is
unchanged.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

LOGGER = "iotmon"
# A library logs nothing until the application asks (no "lastResort" output).
logging.getLogger(LOGGER).addHandler(logging.NullHandler())
# LogRecord attributes that are not user-supplied extra fields
_RESERVED = set(vars(logging.LogRecord("x", 0, "x", 0, "x", None, None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """{"ts": ..., "level": ..., "logger": ..., "event": ..., **extra}"""

    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        doc.update({k: v for k, v in vars(record).items() if k not in _RESERVED and not k.startswith("_")})
        if record.exc_info:
            doc["error"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    """event key=value key=value: readable, and still greppable."""

    def format(self, record: logging.LogRecord) -> str:
        extra = {k: v for k, v in vars(record).items() if k not in _RESERVED and not k.startswith("_")}
        when = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        fields = " ".join(f"{k}={json.dumps(v, default=str) if isinstance(v, (str, list, dict)) else v}"
                          for k, v in extra.items())
        return f"{when} {record.levelname:<7} {record.getMessage()}" + (f" {fields}" if fields else "")


def setup(fmt: str | None, path: str | None = None, level: str = "info") -> logging.Logger:
    """Configure the 'iotmon' logger. With neither a format nor a file, it
    stays silent (NullHandler)."""
    log = logging.getLogger(LOGGER)
    for h in list(log.handlers):
        log.removeHandler(h)
    log.propagate = False
    if not fmt and not path:
        log.addHandler(logging.NullHandler())
        return log
    handler = logging.FileHandler(path, encoding="utf-8") if path else logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if (fmt or "json") == "json" else TextFormatter())
    log.addHandler(handler)
    log.setLevel(level.upper())
    return log


def get() -> logging.Logger:
    return logging.getLogger(LOGGER)
