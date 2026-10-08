# Roadmap

| Stage | Goal | Status |
|---|---|---|
| **Week 1: networking foundation** | Capture/ingest traffic, produce `TIME / SOURCE / DESTINATION / PROTOCOL / PORT` records, Docker lab with simulated devices, explain what the monitor sees ([write-up](01-networking-foundation.md)) | ✅ done |
| **Week 2: device discovery & inventory** | Inventory built from observed traffic (MAC, IPs, first/last seen, protocols, connections), persistent asset register with approve workflow, `New IoT device detected` events, IP-conflict (ARP spoofing) and IP-change events, validated live in the lab ([write-up](02-device-inventory.md)) | ✅ done |
| **Week 3: detection engine** | Rule IDs DET-001 to DET-008; new baseline-driven rules for abnormal connection rate (DET-003), unusual ports (DET-004) and unexpected external connections (DET-005); learned and persisted behavioural baseline; evidence-record alerts; six controlled test scenarios (one per core rule plus a near miss) replayed in tests and run live in the Docker lab ([write-up](03-detection-engine.md)) | ✅ done |
| **Week 4: IoT protocols** | MQTT visibility (clients, topics, values, subscriptions) in SQLite, CLI and dashboard; DET-009 for new broker clients, message bursts, new/spoofed topics and broad subscriptions against a learned MQTT baseline; lab motor drive publishing `factory/pressure` and `factory/motor/rpm`; three MQTT scenarios, recorded and live ([write-up](04-iot-protocols.md)) | ✅ done |
| **Week 5: logging & dashboard** | SQLite as the system of record: alert triage status and notes, `runs` table, versioned schema with in-place upgrades, retention (`db prune`); security posture (CRITICAL / AT RISK / WATCH / OK) with reasons and device risk ranking; dashboard posture banner, headline numbers, alert filters, triage and CSV export; `iotmon status`, `alerts`, `db` commands; validated live in the Docker lab ([write-up](05-logging-dashboard.md)) | ✅ done |
| **Week 6: recruiter-ready project** | src layout, `config.yaml` + `rules/detection_rules.yaml` (rule catalogue as data, checked against the engine by a test), `simulator/`, `screenshots/`; README restructured (problem → … → lessons), architecture diagram, demo GIF (`read --speed`), CI on Python 3.11-3.13, design decisions and lessons learned; lab rebuilt from the new layout, 8/8 live ([write-up](06-project-presentation.md)) | ✅ done |
| **Week 7: OT / ICS expansion** | Modbus/TCP decoding and tracker; OT/IT zones and an allowlisted-communication policy (segmentation); asset device-type, zone and risk score; six OT rules DET-010..015; deterministic `samples/ot-lab.pcap`; a full Docker OT lab (simulated PLC + EWS + HMI) validated live 6/6 ([write-up](07-ot-ics-expansion.md)) | ✅ done |
| Traffic parsing & device tracking | MQTT / DNS / HTTP / NTP decoding, flows, MAC-based inventory with vendor and role | ✅ done |
| Detection engine | Eight rules, each with positive and negative tests | ✅ done |
| Logging / alerts | SQLite, JSONL, CSV; triage status, run log, retention | ✅ done |
| Security dashboard | Posture, devices, alerts with triage, traffic, severity; web and terminal | ✅ done |
| Next | | |
| | Allowlist of authorised scanners and per-device expected peers ("the sensor only ever talks to the broker") | ☐ |
| | Tune `traffic_spike` for devices with little history: in the live lab the camera's 20 kB upload and the admin's 30 kB snapshot can share a 10 s bucket in the first minutes and cross the 50 kB floor (one false positive per lab start) | ☐ |
| | Inventory: alert when an approved device goes silent (last_seen too old), and enrich the register from DHCP requests (hostname, vendor class) | ☐ |
| | Second, longer port-scan window to catch slow scans | ☐ |
| | DET-005: allow by DNS domain as well as by address (CDNs rotate IPs); baseline per MAC instead of per IP | ☐ |
| | Baseline drift: re-learn on a schedule from approved traffic, with a diff of what changed | ☐ |
| | Ship `alerts.jsonl` to Wazuh/Elastic, plus a Sigma-style rule export | ☐ |
| | Dashboard login, with an `alert_history` table (who changed what, when) for time-to-acknowledge / time-to-resolve metrics | ☐ |
| | Group alerts into incidents (same device, same time window); feed false positives back into thresholds and allowlists | ☐ |
| | DNP3, EtherNet/IP and S7comm decoding (Modbus/TCP done in Week 7); per-register range checks; Modbus/TCP visibility in a fully simulated lab (function codes, unit IDs, which hosts read and write which registers), then DNP3; linking to the [OT/ICS lab](https://github.com/kgiannopoulou/ot-ics-cybersecurity-lab) | ☐ |
| | MQTT: retained-message and QoS anomalies, payload range checks per topic (e.g. rpm outside 1400-1500) | ☐ |
| | TLS SNI / JA3 fingerprints for encrypted-traffic visibility | ☐ |
| | Ingest Mosquitto broker logs (auth failures stay visible under TLS) | ☐ |
| | Run on a Raspberry Pi with a switch SPAN port against real devices | ☐ |
