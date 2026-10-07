# Roadmap

| Stage | Goal | Status |
|---|---|---|
| **Week 1: networking foundation** | Capture/ingest traffic, produce `TIME / SOURCE / DESTINATION / PROTOCOL / PORT` records, Docker lab with simulated devices, explain what the monitor sees ([write-up](01-networking-foundation.md)) | ✅ done |
| **Week 2: device discovery & inventory** | Inventory built from observed traffic (MAC, IPs, first/last seen, protocols, connections), persistent asset register with approve workflow, `New IoT device detected` events, IP-conflict (ARP spoofing) and IP-change events, validated live in the lab ([write-up](02-device-inventory.md)) | ✅ done |
| Traffic parsing & device tracking | MQTT / DNS / HTTP / NTP decoding, flows, MAC-based inventory with vendor and role | ✅ done |
| Detection engine | Port scan, new device, traffic spike, suspicious ports, failed connections, all tested | ✅ done |
| Logging / alerts | SQLite, JSONL, CSV | ✅ done |
| Security dashboard | Devices, alerts, traffic, severity | ✅ done |
| Next | | |
| | Allowlist of authorised scanners and per-device expected peers ("the sensor only ever talks to the broker") | ☐ |
| | Tune `traffic_spike` for devices with little history: in the live lab the camera's 20 kB upload and the admin's 30 kB snapshot can share a 10 s bucket in the first minutes and cross the 50 kB floor (one false positive per lab start) | ☐ |
| | Inventory: alert when an approved device goes silent (last_seen too old), and enrich the register from DHCP requests (hostname, vendor class) | ☐ |
| | Second, longer port-scan window to catch slow scans | ☐ |
| | Ship `alerts.jsonl` to Wazuh/Elastic, plus a Sigma-style rule export | ☐ |
| | Modbus/TCP and DNP3 parsing for OT devices, linking to the [OT/ICS lab](https://github.com/kgiannopoulou/ot-ics-cybersecurity-lab) | ☐ |
| | TLS SNI / JA3 fingerprints for encrypted-traffic visibility | ☐ |
| | Ingest Mosquitto broker logs (auth failures stay visible under TLS) | ☐ |
| | Run on a Raspberry Pi with a switch SPAN port against real devices | ☐ |
