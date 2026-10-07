# Roadmap

| Stage | Goal | Status |
|---|---|---|
| **Week 1: networking foundation** | Capture/ingest traffic, produce `TIME / SOURCE / DESTINATION / PROTOCOL / PORT` records, Docker lab with simulated devices, explain what the monitor sees ([write-up](01-networking-foundation.md)) | ✅ done |
| Traffic parsing & device tracking | MQTT / DNS / HTTP / NTP decoding, flows, MAC-based inventory with vendor and role | ✅ done |
| Detection engine | Port scan, new device, traffic spike, suspicious ports, failed connections, all tested | ✅ done |
| Logging / alerts | SQLite, JSONL, CSV | ✅ done |
| Security dashboard | Devices, alerts, traffic, severity | ✅ done |
| Next | | |
| | Allowlist of authorised scanners and per-device expected peers ("the sensor only ever talks to the broker") | ☐ |
| | Second, longer port-scan window to catch slow scans | ☐ |
| | Ship `alerts.jsonl` to Wazuh/Elastic, plus a Sigma-style rule export | ☐ |
| | Modbus/TCP and DNP3 parsing for OT devices, linking to the [OT/ICS lab](https://github.com/kgiannopoulou/ot-ics-cybersecurity-lab) | ☐ |
| | TLS SNI / JA3 fingerprints for encrypted-traffic visibility | ☐ |
| | Ingest Mosquitto broker logs (auth failures stay visible under TLS) | ☐ |
| | Run on a Raspberry Pi with a switch SPAN port against real devices | ☐ |
