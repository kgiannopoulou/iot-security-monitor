# What I Learned

This project was the vehicle for learning network monitoring, IoT
protocols and detection engineering. These are the lessons that changed
how the code is built. Each comes from something that happened during the
six weeks, and links to where it is written up.

---

## Networking

**Packets are not the unit of analysis.** The Week 1 milestone was a
table with one line per packet, which is accurate and, on its own, almost
useless. A security
question is about devices ("what is this Raspberry Pi?"), conversations
("who talks to the broker?") and sessions ("what did this MQTT client
publish?"). Most of the monitor's code turns packets into those three
things: the inventory, the flow table and the MQTT tracker.
([Week 1](01-networking-foundation.md))

**Direction is a deduction, not a field.** A packet doesn't say which side
is the client. The rule I settled on: the *service port* is the
well-known one, and otherwise the lower one. `50432 → 1883` and its reply
`1883 → 50432` are the same MQTT conversation. Getting this wrong would
double every count and break the port-scan rule. ([Week 1](01-networking-foundation.md))

**Where you capture decides what you can see.** On the internet gateway
you see the C2 traffic but not the scan between two devices. On the switch
(SPAN port, or the Docker bridge in the lab) you see both. That choice
comes before any code. ([Week 1, section 9](01-networking-foundation.md#9-where-the-monitor-sits-and-why-it-sees-everything))

## Asset visibility

**A passive inventory only knows devices that talk.** In the first live run
of the Week 3 scenarios, the Docker gateway (172.28.0.1) raised a "new
device" alert. It was there all along, but it never sends anything until
it has to answer an error, so the monitor had never seen it. The monitor
was right by its own definition, and the fix was site configuration, not
code: infrastructure that only speaks when something goes wrong belongs in
the known-devices list. Real OT inventories combine passive observation
with documentation for the same reason. ([Week 3](03-detection-engine.md))

**Key by the thing that doesn't change.** IP addresses move with DHCP;
the network card doesn't. Keying the inventory by MAC keeps it stable and,
as a side effect, makes ARP spoofing visible as "two MACs claim one IP".
([Week 2](02-device-inventory.md))

## Detection engineering

**Every threshold needs a sentence behind it.** A bare number like
"alert above 50 connections" can't be defended: nobody can say why 50, so
nobody can say whether 49 is safe. The rules read like
`max(20, 5 × this device's busiest minute)`: relative to the device,
with a floor so that quiet devices don't alert on noise. I can defend
that in a review, and the near-miss scenario checks the boundary.
([Week 3](03-detection-engine.md), [rules](detection-rules.md))

**Test the silence, not only the alarm.** A test suite of attacks that
fire proves nothing about false positives. The near-miss scenario does
every kind of suspicious thing at 80% of the threshold and must produce
zero alerts, and the sample capture's five-minute baseline must too. Those
two tests are what make the other tests mean something.
([Week 3](03-detection-engine.md))

**Some attacks are only visible relative to the device.** The connection
flood scenario uses the right peer, the right port and valid credentials.
There is no scan, no failure and no volume spike, so every fixed rule
stays quiet. Only "this sensor normally opens one connection a minute"
catches it. ([Week 3](03-detection-engine.md))

**Copying logic between rules is how you get false positives.** In Week 4
the motor drive was flagged for a "message burst" before any scenario had
started. I had copied the learning logic from the connection-rate rule,
where anything above the floor during learning counts as suspicious. That
is right for connection attempts, but a fast telemetry device sends 60
messages a minute by design. The fix (learn whatever rate you see during
learning, never alert on rate then) came with a regression test and a
written trade-off: a burst during learning is learned as normal.
([Week 4](04-iot-protocols.md))

**Not every false positive should be fixed in code.** The camera's upload
and the admin's snapshot can land in the same 10-second bucket in the
first minutes of the lab, which looks like a traffic spike. Raising the
floor would blind the rule to real exfiltration on quiet devices. So it
is documented on the roadmap, and since Week 5 it can be closed as a false
positive with a note. Part of detection engineering is deciding which
false positives to live with. ([Week 5](05-logging-dashboard.md))

## IoT and OT protocols

**IoT security is protocol security.** The most dangerous scenario, the
temperature sensor publishing a fake value on the motor drive's
`factory/motor/rpm` topic, happens on an established, authenticated,
expected connection. Every network-level rule is blind to it. Only
decoding MQTT and knowing which device owns which topic catches it. That
is the strongest argument for protocol-aware monitoring on OT networks,
and why Modbus/TCP is next. ([Week 4](04-iot-protocols.md))

**Detection doesn't replace prevention.** The broker in the lab uses one
shared account for every device, so nothing could have stopped the spoofed
value. Per-device credentials and topic ACLs are the preventive control;
DET-009 is the detective one. A monitoring project should say which
controls it assumes and which it compensates for. ([Week 4](04-iot-protocols.md))

## Building a tool other people use

**A security tool is finished when someone else can read its output.**
After Week 4 the monitor produced correct alerts that nobody could act on:
twelve lines, no priority, no history. Week 5's posture ("AT RISK, because
...") and triage (who decided what, and why) mattered more than another
rule would have. ([Week 5](05-logging-dashboard.md))

**"Acknowledged" is not "safe".** If acknowledging an alert cleared it from
the posture, *Ack all* would be the fastest way to a green dashboard. So
only resolved or false-positive alerts stop counting, and both take a
note.
([Week 5](05-logging-dashboard.md))

**The environment bites.** SQLite's WAL mode lets the monitor and the
dashboard share a file across containers, but opening the same file from
Windows through the Docker Desktop file share silently checkpointed the
containers' write-ahead log away. The fix was a rule in the lab guide
(query the database through the dashboard, not from the host) and a
reminder that "works on my machine" includes the file system.
([lab setup](lab-setup.md))

**Documentation rots unless a test reads it.** When the rule catalogue
moved into `rules/detection_rules.yaml` in Week 6, I added a test that
replays every capture and checks each alert's severity and ATT&CK
technique against the file. The ATT&CK column in a README is easy to get
wrong; a failing test isn't. ([Week 6](06-project-presentation.md))

## If I started again

Looking back over the six weeks:

* I would write the scenario generator first and the detectors second.
  Having the attack and the near miss as files made every rule faster to
  build.
* I would set up the live lab on day one. Each of the three real false
  positives came from the live lab, never from the synthetic captures.
* I would keep the rule catalogue in a data file from the start, rather
  than moving it there at the end.
