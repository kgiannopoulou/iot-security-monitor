# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- README: production considerations; roadmap item for Modbus updated (done in Week 7).
- `CONTRIBUTING.md` and this changelog.

## [1.1.0] - 2026-10-17

### Added
- Confidence scoring for alerts, so benign look-alikes never score high.
- Schema-validated custom rules in YAML.
- SIEM output in ECS JSON, CEF and syslog; structured JSON logs.

## [1.0.0] - 2026-10-08

### Added
- Passive capture and parsing (Ethernet, ARP, IP, TCP/UDP, DNS, HTTP, MQTT), with a test proving no module can transmit.
- Device discovery and an asset inventory keyed by MAC.
- Detection engine with rule ids, per-device behavioural baselines and controlled attack scenarios.
- MQTT protocol monitoring (DET-009).
- SQLite alert log, security posture, triage workflow and web + terminal dashboards.
- OT/ICS expansion: Modbus/TCP decoding, OT/IT zones, allowlisted communication policy, rules DET-010..015, Docker OT lab.
- SOC analyst view: severity, risk scores, MITRE ATT&CK (Enterprise + ICS) mapping, per-alert pcap export and reports.
- CI on every push with a CLI smoke test on the sample captures.

[Unreleased]: https://github.com/kgiannopoulou/iot-security-monitor/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/kgiannopoulou/iot-security-monitor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kgiannopoulou/iot-security-monitor/releases/tag/v1.0.0
