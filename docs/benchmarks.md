# Throughput

```sh
python tools/benchmark.py              # best of 3 per stage, markdown table
python tools/benchmark.py --json
```

Each stage is timed on its own, on the bundled captures, so the bottleneck is visible. Python 3.14,
scapy 2.8, Windows 11, AMD Ryzen 7 5800H:

| Capture | Packets | Read (scapy) | Parse | Detect | Detect + store | End to end |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| iot-lab.pcap | 3,546 | 7,483 pkt/s | 17,368 pkt/s | 7,243 pkt/s | 6,667 pkt/s | 2,634 pkt/s |
| ot-lab.pcap | 1,112 | 8,691 pkt/s | 20,990 pkt/s | 20,077 pkt/s | 13,427 pkt/s | 3,709 pkt/s |

| Stage | What it measures |
| --- | --- |
| Read | scapy reading and dissecting the pcap (`PcapReader`) |
| Parse | dissected packet → `PacketRecord` ([`parser.py`](../src/iotmon/parser.py)) |
| Detect | inventory, flows, baselines, all 15 rules and confidence scoring, no storage |
| Detect + store | the same plus SQLite and `alerts.jsonl` writes |
| End to end | what `iotmon read` does: read + parse + detect + store, one packet at a time |

## What it means

- **About 2,600–3,700 packets/s end to end.** A small IoT/OT segment — sensors publishing every few
  seconds, PLC polling, a camera — is tens to hundreds of packets per second, so one monitor
  process has more than 10× headroom there. It is not a data-centre sensor.
- **scapy is the ceiling.** Reading and dissecting costs as much as all the detection logic; the IoT
  capture's detection stage is slower than the OT one because MQTT state, baselines and nine rules
  see every packet. End to end is lower than any single stage because the stages add up.
- **Scaling path:** keep this detection layer and feed it from a faster parser (Zeek or Suricata
  logs, or a compiled dissector) — the detectors only need `PacketRecord`s. That is the same
  conclusion as the README's Limitations section, now with numbers that anyone can reproduce.
