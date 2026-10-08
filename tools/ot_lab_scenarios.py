"""Run the OT attack scenarios against the live Docker lab (lab/ot/) and check
which rules fired, through the dashboard API. Mirrors tools/lab_scenarios.py.

    cd lab/ot && docker compose up -d --build      # wait for data/ot-lab/baseline.json
    python tools/ot_lab_scenarios.py

The office PC (192.168.10.130, IT zone) runs the Modbus attacks; a short-lived
rogue container joins the OT zone; the PLC container itself makes the outbound
connection. The attack code is simulator/ot_attacks.py.
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
ATTACKS = (ROOT / "simulator" / "ot_attacks.py").read_bytes()
OFFICE = ["docker", "exec", "-i", "ot-lab-office-1", "python", "-"]
PLC = ["docker", "exec", "-i", "ot-lab-plc-1", "python", "-"]
# A rogue device that joins the OT control zone (lower half of the bridge).
ROGUE = ["docker", "run", "--rm", "-i", "--network", "ot-lab_otlab", "--ip", "192.168.10.66",
         "--mac-address", "b8:27:eb:00:00:a6", "ot-lab-office", "python", "-"]

STEPS = [
    ("det-012-segmentation", "Office PC (IT) reads the PLC over Modbus", OFFICE, "unauthorized-read",
     {"DET-011", "DET-012"}),
    ("det-011-write", "Office PC writes the RPM setpoint", OFFICE, "unauthorized-write", {"DET-011"}),
    ("det-014-modbus-flood", "Office PC floods the PLC with register reads", OFFICE, "flood", {"DET-014"}),
    ("det-013-telnet", "Office PC opens a Telnet session to the PLC", OFFICE, "telnet", {"DET-013"}),
    ("det-010-rogue-asset", "A rogue device joins the OT zone and reads the PLC", ROGUE, "unauthorized-read",
     {"DET-010"}),
    ("det-015-plc-external", "The PLC connects out to an internet host", PLC, None, {"DET-015"}),
]

PLC_EXTERNAL = b"import socket\ntry:\n socket.create_connection(('198.51.100.23',443),2)\nexcept OSError:\n pass\n"


def api(path: str, port: int):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
        return json.load(r)


def fired_rules(port: int, since: float) -> set[str]:
    return {a["rule_id"] for a in api("/api/alerts?limit=1000", port) if a["ts"] >= since}


def run_step(cmd, stdin_action, port) -> None:
    payload = ATTACKS if stdin_action else PLC_EXTERNAL
    args = cmd + ([stdin_action] if stdin_action else [])
    subprocess.run(args, input=payload, capture_output=True, timeout=120)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--only", help="run just the named scenario")
    args = ap.parse_args()

    try:
        api("/api/state", args.port)
    except OSError:
        print(f"dashboard not reachable on :{args.port} - is the OT lab up?", file=sys.stderr)
        return 1

    rows, ok = [], True
    for name, story, cmd, action, expect in STEPS:
        if args.only and name != args.only:
            continue
        print(f"== {name}: {story}")
        t0 = time.time()
        run_step(cmd, action, args.port)
        time.sleep(8)  # let the monitor commit (every 2 s) and the flow settle
        fired = fired_rules(args.port, t0)
        hit = expect & fired
        passed = expect <= fired
        ok &= passed
        print(f"   expected {sorted(expect)}  fired {sorted(fired)}  -> {'PASS' if passed else 'FAIL'}")
        rows.append((name, expect, hit, passed))

    print(f"\n{'SCENARIO':<26} {'EXPECTED':<20} {'FIRED':<20} RESULT")
    for name, expect, hit, passed in rows:
        print(f"{name:<26} {','.join(sorted(expect)):<20} {','.join(sorted(hit)) or '-':<20} "
              f"{'PASS' if passed else 'FAIL'}")
    n = sum(p for *_, p in rows)
    print(f"\n{n}/{len(rows)} OT scenarios passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
