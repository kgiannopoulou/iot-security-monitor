# Week 6: Turning It Into a Presentable Project

**Goal:** someone who has never seen the project understands what it does,
how it is built and why, in a few minutes, and can run it in one more.

Weeks 1-5 built the monitor. Week 6 is about how it reads: the repository
layout, configuration a reviewer can follow, a README that tells the story
in order, an architecture diagram, a demo, and a written account of the
design decisions and what I learned.

---

## 1. Repository layout

The brief suggested this structure:

```
README.md  requirements.txt  config.yaml
src/  dashboard/  rules/  simulator/  tests/  screenshots/  docs/
```

I adopted it, with one deliberate difference: the Python package keeps
its module names and lives in `src/iotmon/` (a standard *src layout*)
instead of being flattened into `src/monitor.py`, `src/detector.py` and
so on.

| Brief | This repository | Why |
|---|---|---|
| `config.yaml` | [`config.yaml`](../config.yaml) | Site settings: monitored networks, learning period, flow timeout |
| `rules/detection_rules.yaml` | [`rules/detection_rules.yaml`](../rules/detection_rules.yaml) | The rule catalogue moved out of code (section 2) |
| `src/monitor.py` | `src/iotmon/capture.py`, `parser.py`, `pipeline.py` | Capture, decoding and wiring are three jobs |
| `src/device_tracker.py` | `src/iotmon/inventory.py`, `assets.py` | Observed devices vs the approved asset register |
| `src/detector.py` | `src/iotmon/detections.py`, `baseline.py`, `mqtt.py` | Nine detectors plus the per-device baseline and the MQTT tracker they use |
| `src/alerts.py` | `src/iotmon/models.py` (`Alert`), `state.py` | The evidence record, and the posture built from all alerts |
| `src/database.py` | `src/iotmon/storage.py` | SQLite schema, triage, retention |
| `dashboard/app.py` | `src/iotmon/dashboard/app.py` | Inside the package, so `pip install` ships it and `iotmon dashboard` finds it |
| `simulator/iot_devices.py` | [`simulator/iot_devices.py`](../simulator/iot_devices.py), [`simulator/attacks.py`](../simulator/attacks.py) | The simulated devices and the controlled attacks, moved from `lab/devices/` and `lab/scenarios/` |
| `tests/test_detection.py` | `tests/` (11 files) | One file per area: parser, detections, scenarios, end to end, inventory, MQTT, dashboard, logging, rules/config, OT, analyst |
| `screenshots/` | [`screenshots/`](../screenshots) | Architecture diagram, dashboard screenshots, demo GIF |
| `docs/architecture.md` | [`docs/`](.) | Architecture plus weekly write-ups, rules, design decisions, lessons learned |

Why not flatten? Renaming nine working modules to match a template would
have touched every import and test for no change in behaviour, and the
current names say what each module does. The src layout itself is the
part that matters: the tests import the installed package, never the
working directory by accident, and `src/iotmon/` is visibly "the product"
while `tools/`, `simulator/`, `lab/` and `tests/` support it.

The move was checked the same way as every other week: the full test
suite, then a rebuild of the Docker lab from the new layout (the device
image now builds from `simulator/`) and the eight live scenarios
([transcript](sample-output/live-lab-week6.txt)):

```
8/8 live scenarios passed
```

## 2. Rules and configuration as data

Until Week 5, thresholds lived in a TOML file inside the package and rule
IDs and names in a Python dictionary. Now:

* **[`rules/detection_rules.yaml`](../rules/detection_rules.yaml)** is the
  single source for the rule catalogue: ID, detector, name, description,
  possible severities, ATT&CK techniques, enabled flag, and every
  threshold and window with a comment explaining it. `models.RULES` (the
  IDs in alerts) is built from it.
* **[`config.yaml`](../config.yaml)** holds the site settings.
* **A site config** (`--config`) overrides only the keys it sets, including
  rule settings under `detections:`. The lab's
  [`lab/monitor.yaml`](../lab/monitor.yaml) changes two keys. Old TOML site
  configs still load.
* **`--rules FILE`** swaps in another rule file, and `iotmon rules -v`
  prints the catalogue with its thresholds.

The risk with documentation in a data file is drift: the ATT&CK column
says one thing and the code raises another. So
[`tests/test_rules_config.py`](../tests/test_rules_config.py) replays the
sample capture and all ten scenario captures and fails if any alert's
severity or ATT&CK technique isn't declared for its rule in the file. It
also checks that every detector has exactly one rule, that site overrides
merge key by key, that a disabled rule really is off, and that malformed
rule files are rejected.

## 3. The README

The README now follows the brief's order: **problem → architecture →
implementation → detections → demonstration → results → limitations →
future improvements → what I learned**. Each section is short and links
to the detailed write-up, so a reviewer can stop at any depth.

* **Problem** explains why IoT/OT networks need *passive, behaviour-based,
  protocol-aware* monitoring, which justifies every later choice.
* **Results** collects the numbers: 12 alerts covering the whole
  intrusion, 0 false positives on the baseline, 10/10 recorded and 8/8
  live scenarios, 106 tests in CI, measured throughput, and the three
  false positives found live and what each one changed.
* **Limitations** is honest about TLS, baseline poisoning, thresholds,
  scale, the missing login and the simulated hardware.

## 4. Architecture diagram and demo

* **[`screenshots/architecture.svg`](../screenshots/architecture.svg)**
  (plus a PNG) shows the five stages of the brief's pipeline with the real
  components in each, the two config files, and the one write back
  (triage). It is hand-written SVG, so it renders sharply on GitHub and
  diffs like code.
* **[`screenshots/demo.gif`](../screenshots/demo.gif)** shows the dashboard
  during a 16× replay of the sample capture: NO DATA → OK (normal
  traffic) → WATCH (a rogue device appears) → CRITICAL (C2 traffic). It is
  recorded by [`tools/record_demo.py`](../tools/record_demo.py), so it can
  be regenerated after any dashboard change. That needed one new feature,
  `iotmon read --speed X`, which replays a capture at its own pace sped up
  X times, turning a pcap into a live demo.

## 5. Continuous integration

[`.github/workflows/tests.yml`](../.github/workflows/tests.yml) installs
the package and runs the test suite on Python 3.11, 3.12 and 3.13 on every
push, then smoke-tests the CLI (`read`, `status`, `rules`) on the sample
capture. The badge at the top of the README shows the result.

## 6. Design decisions and lessons learned

The brief's most important point is that a junior candidate is asked to
*explain* the design more than to show volume. Two documents are written
for that conversation:

* **[Design decisions](design-decisions.md):** fourteen questions an
  interviewer could ask, from "why passive?" and "why per-device
  baselines?" to "why does an acknowledged alert still count?", each with
  the alternatives and the trade-off.
* **[Lessons learned](lessons-learned.md):** what changed my thinking, tied
  to the real incidents in Weeks 1-6: the silent gateway, the motor drive
  flagged during learning, the camera spike kept as a known false
  positive, the WAL file-share problem, spoofed telemetry being invisible
  at the network level.

## Files

| What | Where |
|---|---|
| Config and rules | [`config.yaml`](../config.yaml), [`rules/detection_rules.yaml`](../rules/detection_rules.yaml), [`src/iotmon/config.py`](../src/iotmon/config.py) |
| `iotmon rules`, `read --speed` | [`src/iotmon/cli.py`](../src/iotmon/cli.py) |
| Rule-file tests | [`tests/test_rules_config.py`](../tests/test_rules_config.py) |
| Demo recorder | [`tools/record_demo.py`](../tools/record_demo.py) |
| CI | [`.github/workflows/tests.yml`](../.github/workflows/tests.yml) |
| Diagram, screenshots, GIF | [`screenshots/`](../screenshots) |
| Live check after the move | [`live-lab-week6.txt`](sample-output/live-lab-week6.txt) |
