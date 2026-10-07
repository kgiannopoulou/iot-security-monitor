# Week 1: Networking Foundation and What the Monitor Sees

**Milestone:** be able to explain exactly what the monitor sees and why.

This document covers the networking concepts the monitor depends on, each tied
to real output from this project's lab. Every example below was captured by
`iotmon` itself, either live from the Docker lab
([`sample-output/live-lab-capture.txt`](sample-output/live-lab-capture.txt)) or
from the bundled sample capture
([`sample-output/sample-pcap-capture.txt`](sample-output/sample-pcap-capture.txt)).

---

## 1. The first monitor output

```
TIME      SOURCE           DESTINATION      PROTOCOL  PORT  APP       INFO
06:34:27  172.28.0.20      172.28.0.10      TCP       1883  MQTT      PUBLISH factory/line1/temp
06:34:27  172.28.0.10      172.28.0.20      TCP       1883  MQTT      [A]
06:34:36  172.28.0.21      172.28.0.53      UDP         53  DNS       query api.vendor-cloud.lab
06:34:36  172.28.0.53      172.28.0.21      UDP         53  DNS       answer api.vendor-cloud.lab -> 172.28.0.30
06:34:36  172.28.0.21      172.28.0.30      TCP         80  HTTP      [S]
06:34:36  172.28.0.30      172.28.0.21      TCP         80  HTTP      [SA]
06:34:36  172.28.0.21      172.28.0.30      TCP         80  HTTP      [A]
06:34:36  172.28.0.21      172.28.0.30      TCP         80  HTTP      POST 172.28.0.30/checkin
```

Reading it line by line:

| Line | What happened |
|---|---|
| 1-2 | The temperature sensor (`.20`) publishes a reading to the MQTT broker (`.10`). The broker's reply is a bare TCP ACK `[A]`: MQTT QoS 0 has no application-level acknowledgement, so TCP's delivery receipt is the only reply. |
| 3-4 | The smart plug asks the lab DNS server (`.53`) for its cloud's address. One UDP packet out, one back. |
| 5-7 | The plug opens a TCP connection to the cloud: the **three-way handshake**, SYN `[S]`, SYN-ACK `[SA]`, ACK `[A]`. |
| 8 | Only now does application data (an HTTP POST) flow. |

Lines 3 to 8 show one device "phoning home": **name resolution, then
connection, then data**. Every IoT device that talks to a cloud does this.

## 2. The layers, and which column each one fills

```
┌─────────────────────────────┐
│ Application  MQTT/HTTP/DNS  │ → APP, INFO   (topic, URL, query name)
├─────────────────────────────┤
│ Transport    TCP / UDP      │ → PROTOCOL, PORT, TCP flags
├─────────────────────────────┤
│ Network      IPv4 / IPv6    │ → SOURCE, DESTINATION
├─────────────────────────────┤
│ Link         Ethernet / ARP │ → MAC addresses (inventory, vendor)
└─────────────────────────────┘
```

`iotmon/parser.py` dissects packets in that order. A packet the monitor cannot
fully decode is still recorded at the deepest layer it did understand, so
traffic is never silently dropped.

### MAC address vs IP address

| | MAC | IP |
|---|---|---|
| Scope | One link (switch / bridge segment) | End to end, across routers |
| Assigned by | Manufacturer (first 3 bytes = vendor **OUI**) | Network config / DHCP |
| Changes when crossing a router? | **Yes**, rewritten at every hop | No (unless NAT) |
| Used by the monitor for | Device identity, vendor guess | Conversations, flows, detection |

This is why the inventory keys devices by **MAC**: on the local segment it is
the most stable identifier. It is also why the vendor column works. MAC
`24:0a:c4:…` belongs to Espressif (the ESP32/ESP8266 chips inside many sensors)
and `44:19:b6:…` to Hikvision.

Two consequences you can see in the data:

* Traffic to the internet leaves through the router. Its **destination MAC is
  the gateway's**, even though the destination IP is the cloud server. In the
  sample capture every packet to `203.0.113.50` carries the router's MAC
  `50:c7:bf:00:00:01`. That is why cloud servers never appear in the
  inventory.
* MACs whose first byte has bit `0x02` set are *locally administered*. They come
  from VMs, containers, and phones that randomise their MAC. The lab's
  un-pinned containers show as `locally administered (virtual / randomised)`.
  A real network running MAC randomisation would weaken MAC-based inventory.

### ARP: the glue between the two

Before `.20` can send an IP packet to `.10` on the same segment, it has to
learn `.10`'s MAC:

```
06:34:27  172.28.0.10   172.28.0.20   ARP   who-has 172.28.0.20 tell 172.28.0.10
06:34:27  172.28.0.20   172.28.0.10   ARP   172.28.0.20 is-at 24:0a:c4:00:00:20
```

The request goes to the broadcast MAC (everyone on the segment receives it);
the reply is unicast. ARP has no IP layer and no ports, so the PORT column is
empty. Because ARP requests are broadcast, *any* device on the segment sees
them. That is how the monitor catches an **ARP sweep**, where a new device asks
for every address in the subnet to find out who is there.

## 3. TCP vs UDP

| | TCP | UDP |
|---|---|---|
| Connection | Yes: handshake `S → SA → A`, teardown `FA … A` | No: each datagram stands alone |
| Delivery | Reliable, ordered, acknowledged | Best effort |
| Seen in the lab as | MQTT (1883), HTTP (80), HTTPS (443), Telnet (23) | DNS (53), NTP (123) |
| What failure looks like | `RST` (port closed), or SYN with no answer (filtered) | Silence, or ICMP "port unreachable" |

Flags are where most of the security signal is:

| Flags | Meaning | Detection use |
|---|---|---|
| `S` | SYN: "I want to connect" | Counting SYNs to many ports = **port scan** |
| `SA` | SYN-ACK: "port is open, OK" | A SYN-ACK from port 23 = **Telnet is exposed** |
| `RA` / `R` | Reset: "nothing listening here" / abort | Many RSTs to one service = **failed connections** |
| `PA` | Push+ACK: carries data | Where application payload lives |
| `FA` | FIN: orderly close | Normal end of a flow |

From the sample attack, a SYN scan as seen by the monitor:

```
10:35:10  192.168.1.66  192.168.1.22  TCP   22  SSH     [S]
10:35:10  192.168.1.22  192.168.1.66  TCP   22  SSH     [RA]   ← closed
10:35:10  192.168.1.66  192.168.1.22  TCP   23  TELNET  [S]
10:35:10  192.168.1.22  192.168.1.66  TCP   23  TELNET  [SA]   ← open!
10:35:10  192.168.1.66  192.168.1.22  TCP   23  TELNET  [R]    ← scanner never completes the handshake
```

## 4. Ports, and the "PORT" column

A client connects **from** a random ephemeral port (for example 49152-65535 on
Linux) **to** a fixed, well-known service port. The request is `50432 → 1883`
and the reply is `1883 → 50432`. Printing both raw ports would make every
conversation look different, so the monitor prints the **service port** for
both directions (`models.service_port`):

1. If the destination port is a known service (1883, 53, 80…), use it.
2. Otherwise, if the source port is a known service, use that (it's a reply).
3. Otherwise, use the lower of the two.

The same rule decides which side of a flow is the client and which is the
server, and lets the inventory learn which services a device *offers*. The
camera answered on 23 and 80, so its services are `23,80`.

> **Caveat: a port is a convention, not a guarantee.** The monitor labels
> UDP/80 as "HTTP" because of the port number, and the sample's UDP flood to
> ports 53/80/443/123 shows up in the chart as DNS/HTTP/HTTPS/NTP. Malware and
> tunnels use well-known ports precisely because of this. The INFO column only
> appears when the payload actually parsed as that protocol, so an "HTTP" row
> without a request line deserves a second look.

## 5. DNS

DNS turns names into addresses. It is one of the most useful things a passive
monitor can see, because a device announces where it is about to connect
*before* it connects:

```
10:36:34  192.168.1.22  192.168.1.1   UDP  53  DNS  query cnc.badbot.example
10:36:34  192.168.1.1   192.168.1.22  UDP  53  DNS  answer cnc.badbot.example -> 198.51.100.23
10:36:35  192.168.1.22  198.51.100.23 TCP 6667 IRC  [S]
```

A camera resolving a name it has never used before, followed by a connection
to an IRC port, is a textbook compromised-device signature.

**Why some DNS is invisible:** in Docker, containers normally resolve through
Docker's embedded resolver at `127.0.0.11`. That traffic stays *inside each
container's network namespace* and never crosses the bridge, so a bridge
monitor never sees it. The lab therefore runs its own DNS server (`dns`,
`172.28.0.53`) and the devices query it explicitly. The same thing happens on
real networks: queries a host answers from its own cache, or sends through
DNS-over-HTTPS, never appear as port 53 traffic on the wire.

## 6. HTTP vs MQTT: two application models

| | HTTP | MQTT |
|---|---|---|
| Pattern | Request → response | Publish / subscribe through a **broker** |
| Connection | Usually short-lived (one exchange per connection in the lab) | **Long-lived**, one TCP session kept open for hours |
| Who talks to whom | Client ↔ server | Every device ↔ broker; devices never talk to each other |
| Visible in cleartext | Method, host, path, status | CONNECT (client ID, **username**), topic names, payloads |
| Secure variant | HTTPS (443) | MQTT over TLS (8883) |

The long-lived MQTT session is why the live capture shows `PUBLISH` packets
without a preceding handshake: the session was opened when the device booted,
before the monitor started. It is also why device names (taken from the MQTT
`CONNECT` client ID) only appear if the monitor was already running when the
device connected. MQTT keeps idle sessions alive with `PINGREQ`/`PINGRESP`.

The broker refusing a login looks like this on the wire. The broker answers
in cleartext, so the monitor can count refused logins:

```
10:36:00  192.168.1.66  192.168.1.10  TCP 1883 MQTT CONNECT id=probe-0 user=devices
10:36:00  192.168.1.10  192.168.1.66  TCP 1883 MQTT CONNACK not authorized
```

## 7. Packets vs flows

A **packet** is one frame on the wire. A **flow** is every packet between the
same client socket and server socket, both directions, until it goes idle
(`iotmon/flows.py`, 60 s idle timeout):

```
client 192.168.1.22:52201 -> server 203.0.113.80:443   TCP/HTTPS   23 pkts  23105 B  CLOSED
```

That one line summarises 23 packets: handshake, 15 upload segments, the
server's reply, and the FIN teardown. Flows answer "who talks to whom, how
much, how long"; packets answer "what exactly was said". Detection uses both:
the port-scan rule counts packets (SYNs), while the dashboard's "top flows"
view and future baselining work on flows.

## 8. Encryption: what the monitor *cannot* see

```
10:30:20  192.168.1.22  203.0.113.80  TCP  443  HTTPS  TLS record, 1400 bytes (encrypted)
```

For HTTPS / MQTT-TLS the monitor still sees **metadata**: who, when, how
much, which port, and (in the TLS handshake) the server name. It cannot see
the **content**. So encrypted traffic can only be analysed by behaviour:
volume, timing, destinations. That is the job of the traffic-spike rule. It is
also why the plaintext protocols (MQTT on 1883, HTTP, Telnet) are both a risk
*and* the most visible traffic on an IoT network.

## 9. Where the monitor sits, and why it sees everything

```
             Docker host (Linux VM on Docker Desktop)
   ┌──────────────────────────────────────────────────────┐
   │   iotlab0  (Linux bridge = virtual switch)           │
   │     ▲   ▲      ▲       ▲        ▲       ▲       ▲    │
   │   veth veth  veth    veth     veth    veth    veth   │
   │     │   │      │       │        │       │       │    │
   │  broker dns  sensor  plug   camera   cloud   admin   │
   │                                                      │
   │   monitor (network_mode: host) ── sniffs iotlab0     │
   └──────────────────────────────────────────────────────┘
```

* A **switch** forwards a unicast frame only to the port where the destination
  MAC lives. A device plugged into an ordinary switch port therefore sees only
  its own traffic plus broadcasts (ARP, DHCP, mDNS). This is why sniffing from
  "just another device" gives a very partial view.
* The Docker bridge `iotlab0` is a virtual switch, but the *host* side of the
  bridge sees every frame that crosses it. Running the monitor in the host's
  network namespace (`network_mode: host`) and capturing on `iotlab0` is the
  equivalent of a **SPAN / mirror port** on a physical switch. This is how
  industrial IDS sensors (Suricata, Zeek, Nozomi, Claroty) are deployed in
  OT networks.
* What it **does not** see: traffic between processes inside one container
  (loopback), Docker's embedded DNS (see §5), and anything that doesn't cross
  the bridge.

On real hardware the options are, in order of preference: a switch SPAN port,
a network TAP, or running the monitor on the router/gateway itself.

## 10. IoT architecture in this lab

```
  Field / device layer        Edge / network layer             Cloud / app layer
 ┌──────────────────┐       ┌────────────────────────┐       ┌──────────────────┐
 │ temp-sensor .20  │─MQTT─▶│                        │       │ vendor cloud .30 │
 │ smart-plug  .21  │─MQTT─▶│ broker .10 (Mosquitto) │       │  (HTTP API)      │
 │ ip-camera   .22  │       │ dns .53                │◀─HTTP─│                  │
 └──────────────────┘       └────────────────────────┘       └──────────────────┘
          │  plug check-in / camera upload over HTTP ────────────────▶ │
          ▲
  admin .5 ── HTTP GET /snapshot.jpg (camera web UI)
```

The same three tiers appear in OT (Purdue model levels 0-1 → 2-3 → 4-5).
The security-relevant traffic lives at the boundaries: device → broker
(credentials, topics), device → cloud (what leaves the site), and anything
reaching the device directly (web UI, Telnet). Those are the boundaries the
detection rules watch.

## Self-check

Questions you should be able to answer from the monitor's output alone:

1. Why does the broker's reply to a PUBLISH show `[A]` and no MQTT info? *(QoS 0: TCP ACK only)*
2. Why does a cloud server never appear in the device inventory? *(off-subnet; its frames carry the gateway MAC)*
3. Why is the PORT column the same for a request and its reply? *(service port rule)*
4. How do you tell a closed port from a filtered one? *(RST vs no reply)*
5. Why can't the monitor read the camera's uploads, and what can it still tell you about them? *(TLS; metadata, volume, timing)*
6. Why would a monitor plugged into a normal switch port miss most of this traffic? *(unicast forwarding; needs SPAN/TAP)*
