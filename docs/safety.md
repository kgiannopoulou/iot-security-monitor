# Passive monitoring: safety and limits

IoT and especially OT networks are fragile: a PLC can fault on an unexpected packet, and a
"harmless" scan has stopped production lines. This monitor is built so that it cannot be the cause.

## What the monitor does — and never does

| It does | It never does |
| --- | --- |
| Listen to a copy of the traffic (SPAN / mirror port, network TAP, or a pcap) | Send a packet on the monitored network: no probing, scanning, ARP, ping, or "active fingerprinting" |
| Decode packets in memory and write to its own SQLite / JSONL files | Modify, block, drop or inject traffic (it is not inline, not an IPS) |
| Optionally forward alerts to a SIEM over the management network (`--syslog`, opt-in) | Talk to the devices it monitors, log into them, or poll them |

This is enforced by a test, not just a promise:
[`test_the_monitor_never_transmits_on_the_monitored_network`](../tests/test_integrations.py) fails
if any module in `src/iotmon/` calls a scapy send function (`send`, `sendp`, `sr`, `sr1`, `srp`…) or
opens a network socket — the only socket allowed is the opt-in syslog forwarder in `siem.py`.

The attack traffic in this repository exists only as **synthetic captures**
([`tools/generate_sample_pcap.py`](../tools/generate_sample_pcap.py)) and in the isolated Docker
labs' simulator scripts ([`simulator/`](../simulator)), which are separate from the monitor and only
target the lab's own containers.

## Deploying it safely

- **Use a mirror port or a TAP**, never inline. A TAP fails open: if the monitor host dies, traffic
  still flows.
- **Receive-only interface.** On the capture NIC, no IP address, ARP off (`ip link set eth1 arp off`),
  and ideally a TAP with no transmit path. The management interface (dashboard, syslog) is separate.
- **Capture privileges only.** Grant `CAP_NET_RAW` (and `CAP_NET_ADMIN` for promiscuous mode) to the
  capture process instead of running it as root. (The lab's Docker image currently runs as root
  inside its container; a non-root image with those capabilities is on the [roadmap](roadmap.md).)
- **The dashboard binds to 127.0.0.1** and has no login; reach it over SSH tunnelling, don't expose it.
  `--read-only` removes triage actions.
- **Data stays local.** Packet metadata, MQTT topics/values and DNS names are written to `data/`;
  treat that directory as sensitive (it is git-ignored) and set retention with `iotmon db prune`.
- **Get authorisation.** Monitoring traffic is interception: only capture networks you own or are
  authorised in writing to monitor, and follow your organisation's privacy rules for payload data.

## Limits of a passive monitor

- **It detects, it doesn't prevent.** An unauthorized Modbus write is reported after it was sent;
  stopping it is the firewall's job (see the companion
  [OT/ICS lab](https://github.com/kgiannopoulou/ot-ics-cybersecurity-lab) for the conduit firewall).
- **It sees only what the mirror port sees.** Traffic between two devices on another switch, or
  dropped by an oversubscribed SPAN port under load, is invisible. Losses show up as gaps, not
  errors.
- **Encrypted traffic** (MQTT over TLS, HTTPS) shows who talks to whom and how much, not what.
- **Throughput**: about 2,600–3,700 packets/s end to end ([benchmarks.md](benchmarks.md)) — right for
  an IoT/OT segment, not for a core link.
- **A baseline learned from compromised traffic is wrong.** Learn from a reviewed capture
  (`iotmon baseline learn`) where possible.
