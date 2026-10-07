"""Glue: source -> parser -> inventory / flows / detections -> storage."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Iterable

from .detections import DetectionEngine
from .display import Printer
from .flows import FlowTable
from .inventory import Inventory
from .models import Alert, PacketRecord
from .storage import Storage


class Monitor:
    def __init__(self, config: dict, storage: Storage | None = None, printer: Printer | None = None):
        self.config = config
        self.inventory = Inventory(config["network"]["lab_networks"])
        self.flows = FlowTable(idle_timeout=float(config["flows"].get("idle_timeout_s", 60)))
        self.engine = DetectionEngine(config["detections"], self.inventory)
        self.storage = storage
        self.printer = printer
        self.alerts: list[Alert] = []
        self.packets = 0
        self.protocols: Counter = Counter()
        self._last_commit = time.monotonic()

    def process(self, rec: PacketRecord) -> list[Alert]:
        self.packets += 1
        self.protocols[rec.app or rec.protocol] += 1
        new_device = self.inventory.update(rec)
        expired = self.flows.update(rec)
        alerts = self.engine.process(rec, new_device)

        if self.printer:
            self.printer.packet(rec)
        self._emit(alerts)
        if self.storage:
            self.storage.packet(rec)
            if expired:
                self.storage.flows(expired)
            if time.monotonic() - self._last_commit > 2:
                self.storage.devices(list(self.inventory.devices.values()))
                self.storage.commit()
                self._last_commit = time.monotonic()
        return alerts

    def run(self, source: Iterable[PacketRecord]) -> None:
        try:
            for rec in source:
                self.process(rec)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self) -> None:
        self._emit(self.engine.flush())
        if self.storage:
            self.storage.flows(self.flows.drain())
            self.storage.devices(list(self.inventory.devices.values()))
            self.storage.close()
            self.storage = None

    def _emit(self, alerts: list[Alert]) -> None:
        for a in alerts:
            self.alerts.append(a)
            if self.printer:
                self.printer.alert(a)
            if self.storage:
                self.storage.alert(a)
