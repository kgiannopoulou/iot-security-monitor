# Contributing

Thanks for taking a look. This is a personal portfolio project, but issues and
pull requests are welcome — especially detection ideas with a capture that
reproduces them.

## Development setup

Python 3.11+. No admin rights or Docker needed for development: the tests and
the demo run on the bundled synthetic captures.

```bash
git clone https://github.com/kgiannopoulou/iot-security-monitor.git
cd iot-security-monitor
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest
iotmon read samples/iot-lab.pcap && iotmon status   # see the README quick start
```

The live Docker lab is optional — see [docs/lab-setup.md](docs/lab-setup.md).

## Adding or changing a detection

1. Give it the next free rule id (`DET-0xx`) and add it to `rules/detection_rules.yaml` with its
   ATT&CK mapping, severity and documented blind spots
   ([docs/detection-rules.md](docs/detection-rules.md)).
2. Add a **positive** test (the attack fires) and a **near-miss** test (a
   benign look-alike just under the threshold does not).
3. If it needs traffic the samples don't have, add a small deterministic
   capture generator under `tools/` rather than a real-world pcap.
4. The monitor must stay passive: a test fails if any module can transmit
   packets. Don't add active probing.

## Workflow

* Branch from `main` (`feat/…`, `fix/…`, `docs/…`), keep changes focused.
* Conventional Commits: `feat: detect Modbus writes outside maintenance windows`,
  `fix: ignore DHCP renewals in new-peer rule`, `test: near miss for DET-004`.
* Open a pull request with what changed, why and how it was tested. CI runs
  the full test suite on every push and pull request.

## Safety

Only run the monitor on networks you own or are authorised to monitor. See
[docs/safety.md](docs/safety.md).
