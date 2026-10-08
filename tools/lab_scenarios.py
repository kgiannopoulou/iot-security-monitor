"""Run the controlled test scenarios against the live Docker lab and check
which rules fired, through the dashboard API.

    cd lab && docker compose up -d --build      # wait for data/lab/baseline.json
    python tools/lab_scenarios.py

DET-001/002 run in a short-lived "rogue" container (Raspberry Pi MAC, new IP);
DET-003/004/005 and the DET-009 burst and spoofing run inside the
temperature-sensor container, playing a compromised device; the new MQTT
client runs in the admin workstation container. The attack code is simulator/attacks.py.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ATTACKS = (ROOT / "simulator" / "attacks.py").read_bytes()
ROGUE = ["docker", "run", "--rm", "-i", "--network", "iot-lab_iotlab", "--ip", "172.28.0.66",
         "--mac-address", "b8:27:eb:00:00:66", "iot-lab-temp-sensor", "python", "-"]
SENSOR = ["docker", "exec", "-i", "iot-lab-temp-sensor-1", "python", "-"]
ADMIN = ["docker", "exec", "-i", "iot-lab-admin-1", "python", "-"]

STEPS = [
    ("det-001-new-device", "Unknown Raspberry Pi joins and connects to the broker", ROGUE, "hello", {"DET-001"}),
    ("det-002-port-scan", "Same Pi connect-scans 30 ports on the broker", ROGUE, "scan", {"DET-002"}),
    ("det-003-connection-flood", "Sensor opens 30 broker connections in ~10 s", SENSOR, "flood", {"DET-003"}),
    ("det-004-unusual-port", "Sensor opens camera HTTP, then Telnet", SENSOR, "unusual-port", {"DET-004"}),
    ("det-005-external-connection", "Local-only sensor dials 198.51.100.23 (TTL 1)", SENSOR, "external",
     {"DET-005"}),
    ("det-009-new-mqtt-client", "Admin workstation connects to the broker, subscribes to '#'", ADMIN,
     "mqtt-new-client", {"DET-004", "DET-009"}),
    ("det-009-message-burst", "Sensor publishes 10 messages/s for 15 s", SENSOR, "mqtt-burst", {"DET-009"}),
    ("det-009-topic-spoofing", "Sensor publishes on the motor drive's rpm topic", SENSOR, "mqtt-spoof",
     {"DET-009"}),
]


def alerts(api: str) -> list[dict]:
    with urllib.request.urlopen(f"{api}/api/alerts?limit=1000", timeout=5) as resp:
        return json.load(resp)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", default="http://127.0.0.1:8080", help="dashboard URL")
    ap.add_argument("--settle", type=float, default=10, help="seconds to wait for alerts after each step")
    ap.add_argument("--only", metavar="NAME", help="run one scenario, e.g. det-005-external-connection")
    args = ap.parse_args()

    results, failed = [], 0
    for name, story, cmd, action, expect in STEPS:
        if args.only and name != args.only:
            continue
        last_id = max((a["id"] for a in alerts(args.api)), default=0)
        print(f"== {name}: {story}", flush=True)
        run = subprocess.run(cmd + [action], input=ATTACKS, capture_output=True, timeout=120)
        print("   " + (run.stdout or run.stderr).decode(errors="replace").strip().replace("\n", "\n   "))
        time.sleep(args.settle)
        new = sorted((a for a in alerts(args.api) if a["id"] > last_id), key=lambda a: a["id"])
        fired = {a["rule_id"] for a in new}
        ok = fired == expect
        failed += not ok
        for a in new:
            t = time.strftime("%H:%M:%S", time.gmtime(a["ts"]))
            print(f"   {t}  {a['rule_id']}  {a['severity'].upper():<8} {a['title']}")
        results.append((name, ", ".join(sorted(expect)), ", ".join(sorted(fired)) or "none", len(new), ok))

    print(f"\n{'SCENARIO':<30} {'EXPECTED':<18} {'FIRED':<18} {'ALERTS':>6}  RESULT")
    for name, expect, fired, n, ok in results:
        print(f"{name:<30} {expect:<18} {fired:<18} {n:>6}  {'PASS' if ok else 'FAIL'}")
    print(f"\n{len(results) - failed}/{len(results)} live scenarios passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
