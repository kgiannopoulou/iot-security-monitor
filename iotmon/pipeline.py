"""Glue: source -> parser -> inventory / flows / detections -> storage."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Iterable

from .assets import AssetRegister
from .baseline import Baseline
from .detections import DetectionEngine
from .display import Printer
from .flows import FlowTable
from .inventory import Inventory
from .models import Alert, PacketRecord
from .storage import Storage


class Monitor:
    def __init__(self, config: dict, storage: Storage | None = None, printer: Printer | None = None,
                 assets: AssetRegister | None = None, new_asset_status: str = "pending",
                 baseline: Baseline | None = None):
        self.config = config
        self.inventory = Inventory(config["network"]["lab_networks"], config["network"].get("internal_networks"))
        self.flows = FlowTable(idle_timeout=float(config["flows"].get("idle_timeout_s", 60)))
        # An empty register is bootstrapped: the new_device learning period applies,
        # and the devices seen during it are saved as approved.
        self.bootstrap = assets is not None and len(assets) == 0
        self.learning = float(config["detections"].get("new_device", {}).get("learning_period_s", 60))
        if baseline is None:
            bcfg = config.get("baseline", {})
            baseline = Baseline(learning_period=float(bcfg.get("learning_period_s", 120)),
                                window=float(config["detections"].get("connection_rate", {}).get("window_s", 60)))
        self.baseline = baseline
        self._baseline_saved = baseline.frozen  # a loaded baseline is never rewritten
        self.engine = DetectionEngine(config["detections"], self.inventory, None if self.bootstrap else assets,
                                      baseline)
        self.assets = assets
        self.new_asset_status = new_asset_status
        self.added_assets: list[str] = []
        self._last_asset_save = time.monotonic()
        self.storage = storage
        self.printer = printer
        self.alerts: list[Alert] = []
        self.packets = 0
        self._last_ts = 0.0
        self.protocols: Counter = Counter()
        self._last_commit = time.monotonic()

    def process(self, rec: PacketRecord) -> list[Alert]:
        self.packets += 1
        self._last_ts = rec.ts
        self.protocols[rec.app or rec.protocol] += 1
        new_device = self.inventory.update(rec)
        if new_device is not None and self.assets is not None:
            new_device.status = self.assets.status_of(new_device)
        expired = self.flows.update(rec)
        if self.flows.new_flow is not None:
            self.inventory.count_flow(self.flows.new_flow.client_ip, self.flows.new_flow.server_ip)
        alerts = self.engine.process(rec, new_device, self.flows.new_flow)
        if not self._baseline_saved and not self.engine.ctx.learning:
            self.save_baseline(rec.ts)  # learning period just ended

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
        if self.assets is not None and time.monotonic() - self._last_asset_save > 30:
            self.save_assets()  # long live captures keep the register current
        return alerts

    def save_baseline(self, end: float | None = None) -> None:
        first = self.engine.ctx.first_ts
        if first is None:
            return
        self.baseline.mark_learned(first, end if end is not None else self._last_ts, self.packets)
        self.baseline.save()
        self._baseline_saved = True

    def save_assets(self) -> None:
        # Merging the same run repeatedly is safe: overlapping observations are not double counted.
        added = self.assets.merge(list(self.inventory.devices.values()), self._status_for_new)
        self.added_assets += [k for k in added if k not in self.added_assets]
        self.assets.save()
        self._last_asset_save = time.monotonic()

    def _status_for_new(self, dev) -> str:
        first = self.engine.ctx.first_ts
        if self.bootstrap and first is not None and dev.first_seen - first < self.learning:
            return "approved"
        return self.new_asset_status

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
        if not self._baseline_saved:
            self.save_baseline()  # capture ended inside the learning period, or `baseline learn`
        if self.assets is not None:
            self.save_assets()
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
