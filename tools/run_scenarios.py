"""Replay every controlled test scenario and check that exactly the expected
detection rules fire.

    python tools/run_scenarios.py            # summary table + the alerts, exit 1 on any FAIL

Scenarios are defined in tools/generate_scenarios.py; the full kill chain
(samples/iot-lab.pcap) is included as the last row.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from generate_scenarios import SCENARIOS, Scenario  # noqa: E402

from iotmon.capture import read_pcap  # noqa: E402
from iotmon.config import load_config  # noqa: E402
from iotmon.pipeline import Monitor  # noqa: E402

KILL_CHAIN = Scenario("iot-lab (full kill chain)",
                      ("DET-001", "DET-002", "DET-003", "DET-004", "DET-005", "DET-006", "DET-007", "DET-009"),
                      "Rogue Pi: discovery, scan, Telnet, brute force; camera joins a botnet", None)


def replay(path: Path) -> Monitor:
    mon = Monitor(load_config())
    mon.run(read_pcap(str(path)))
    return mon


def main() -> int:
    rows, details, failed = [], [], 0
    for sc in SCENARIOS + [KILL_CHAIN]:
        path = sc.path if sc.inject else ROOT / "samples" / "iot-lab.pcap"
        mon = replay(path)
        fired = sorted({a.rule_id for a in mon.alerts})
        ok = fired == sorted(sc.expect)
        failed += not ok
        rows.append((sc.name, ", ".join(sc.expect) or "none", ", ".join(fired) or "none", len(mon.alerts), ok))
        details.append((sc, mon.alerts))

    print(f"{'SCENARIO':<30} {'EXPECTED':<20} {'FIRED':<20} {'ALERTS':>6}  RESULT")
    for name, expect, fired, n, ok in rows:
        if len(expect) > 20:
            expect = "DET-001..007, 009"
            fired = expect if ok else fired
        print(f"{name:<30} {expect:<20} {fired:<20} {n:>6}  {'PASS' if ok else 'FAIL'}")

    for sc, alerts in details:
        print(f"\n== {sc.name}: {sc.story}")
        if not alerts:
            print("   (no alerts)")
        for a in alerts:
            t = datetime.fromtimestamp(a.ts, tz=timezone.utc).strftime("%H:%M:%S")
            print(f"   {t}  {a.rule_id}  {a.severity.upper():<8} {a.title}")
    print(f"\n{len(rows) - failed}/{len(rows)} scenarios passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
