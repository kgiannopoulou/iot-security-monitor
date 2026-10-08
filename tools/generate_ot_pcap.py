"""Generate samples/ot-lab.pcap: a deterministic, synthetic capture of a small
industrial (OT) network, with a normal baseline followed by OT-specific
attacks. Byte-identical on every run (fixed seed and start time).

The network (one monitored switch spanning two zones):

    OT zone  192.168.10.0/24   PLC .20 (Modbus/TCP server), engineering
                               workstation .10, HMI panel .11, gateway .1
    IT zone  192.168.1.0/24    office PC .50 (the "unknown PC")

Timeline (seconds from start)
    0-300   baseline: the engineering workstation and HMI poll the PLC over
            Modbus (reads), the workstation writes a setpoint now and then,
            NTP / ARP noise. Nothing crosses into OT from outside.
    305     office PC (IT) opens Modbus to the PLC            DET-012, DET-011
    320     office PC writes a holding register               DET-011 (critical)
    335     a rogue device appears in the OT zone (.66)       DET-010
    350     the rogue polls the PLC over Modbus               DET-011
    365     the office PC floods the PLC with register reads  DET-014
    380     someone opens a Telnet session to the PLC         DET-013
    395     the PLC connects out to an internet host (C2)     DET-015

All addresses are RFC 1918 (lab) or RFC 5737 documentation ranges.
"""

from __future__ import annotations

import logging
import struct
import sys
from pathlib import Path

for _name in ("scapy.runtime", "scapy.loading"):
    logging.getLogger(_name).setLevel(logging.ERROR)

import generate_sample_pcap as g  # reuse the Capture/TCP/ARP/NTP helpers
from scapy.layers.inet import TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

START = g.START
OT_GW = ("192.168.10.1", "50:c7:bf:00:00:a1")
PLC = ("192.168.10.20", "00:1b:1b:00:00:20")        # Siemens OUI: Modbus/TCP server
EWS = ("192.168.10.10", "3c:52:82:00:00:10")        # engineering workstation
HMI = ("192.168.10.11", "00:1b:1b:00:00:11")        # HMI panel
ROGUE_OT = ("192.168.10.66", "b8:27:eb:00:00:a6")   # rogue device in the OT zone
OFFICE = ("192.168.1.50", "3c:52:82:00:00:50")      # IT office PC ("unknown PC")
C2 = "198.51.100.23"                                # external host the PLC dials (TEST-NET-2)

# Register the OT/IT MACs so the shared l2() helper emits real source MACs
# (one monitored switch sees every frame; zones are by IP subnet).
g.LOCAL.update({ip: mac for ip, mac in (OT_GW, PLC, EWS, HMI, ROGUE_OT, OFFICE)})


# -- Modbus/TCP payload builders -------------------------------------------- #
def _adu(txid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit) + pdu


def read_req(txid, unit=1, func=3, addr=0, qty=10) -> bytes:
    return _adu(txid, unit, struct.pack(">BHH", func, addr, qty))


def read_resp(txid, unit=1, func=3, values=(0,)) -> bytes:
    data = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    return _adu(txid, unit, struct.pack(">BB", func, len(data)) + data)


def write_req(txid, unit=1, addr=0, value=0) -> bytes:
    return _adu(txid, unit, struct.pack(">BHH", 6, addr, value & 0xFFFF))


def write_resp(txid, unit=1, addr=0, value=0) -> bytes:
    return _adu(txid, unit, struct.pack(">BHH", 6, addr, value & 0xFFFF))


class OtCapture(g.Capture):
    def modbus_poll(self, t, client, server, reads, writes=()):
        """One Modbus session: connect, a few read (and optional write) requests, close."""
        txid = self.rng.randint(1, 60000)
        c2s, s2c = [], []
        for addr, qty in reads:
            c2s.append(Raw(read_req(txid, addr=addr, qty=qty)))
            s2c.append(Raw(read_resp(txid, values=[self.rng.randint(1400, 1500) for _ in range(qty)])))
            txid += 1
        for addr, value in writes:
            c2s.append(Raw(write_req(txid, addr=addr, value=value)))
            s2c.append(Raw(write_resp(txid, addr=addr, value=value)))
            txid += 1
        self.tcp_session(t, client[0], server[0], 502, c2s=c2s, s2c=s2c)

    def modbus_stream(self, t_open, client, server, polls, t_close):
        """One long-lived Modbus session (as real clients keep it) with requests
        spread over time. `polls` is a list of (t, reads, writes)."""
        sport, dport = self.eph(), 502
        cseq, sseq = self.rng.randint(1, 2**31), self.rng.randint(1, 2**31)
        dt = 0.002
        self.add(t_open, g.l2(client, server) / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
        self.add(t_open + dt, g.l2(server, client) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
        self.add(t_open + 2 * dt, g.l2(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        cseq, sseq = cseq + 1, sseq + 1
        txid = self.rng.randint(1, 60000)
        for t, reads, writes in polls:
            for addr, qty in reads:
                req, resp = read_req(txid, addr=addr, qty=qty), read_resp(txid, values=[1450] * qty)
                txid += 1
                self.add(t, g.l2(client, server) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(req))
                cseq += len(req)
                self.add(t + dt, g.l2(server, client) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(resp))
                sseq += len(resp)
            for addr, value in writes:
                req, resp = write_req(txid, addr=addr, value=value), write_resp(txid, addr=addr, value=value)
                txid += 1
                self.add(t + 0.01, g.l2(client, server) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(req))
                cseq += len(req)
                self.add(t + 0.01 + dt, g.l2(server, client) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(resp))
                sseq += len(resp)
        self.add(t_close, g.l2(client, server) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
        self.add(t_close + dt, g.l2(server, client) / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
        self.add(t_close + 2 * dt, g.l2(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))

    def modbus_flood(self, t, client, server, n):
        """One session with many back-to-back register reads (a polling flood / scan)."""
        txid = self.rng.randint(1, 60000)
        c2s = [Raw(read_req(txid + i, addr=i * 10, qty=10)) for i in range(n)]
        s2c = [Raw(read_resp(txid + i, values=[0] * 10)) for i in range(n)]
        self.tcp_session(t, client[0], server[0], 502, c2s=c2s, s2c=s2c)


def baseline(cap: OtCapture, t0: float, t1: float) -> None:
    """Normal OT traffic: the EWS and HMI each hold one Modbus session to the PLC
    and poll it; the EWS writes a setpoint once a minute. NTP / ARP noise."""
    hmi_polls, ews_polls = [], []
    setpoint = 1450
    if t0 == 0:  # the OT gateway answers an ARP early, so it is a known device, not "new"
        cap.arp(2, EWS, OT_GW[0])
    t = t0
    while t < t1:
        hmi_polls.append((t + cap.jitter(0.1), [(0, 10)], []))                 # HMI reads every ~2 s
        if int(t - t0) % 5 == 0:
            ews_polls.append((t + 0.3, [(0, 20), (100, 8)], []))               # EWS reads every ~5 s
        if int(t - t0) % 60 == 0 and t > t0:
            setpoint += 5
            ews_polls.append((t + 0.5, [], [(40, setpoint)]))                  # EWS writes a setpoint
        if int(t - t0) % 30 == 0:
            cap.ntp(t + 0.7, EWS[0])
        if int(t - t0) % 47 == 0:
            cap.arp(t + 0.9, EWS, PLC[0])
        t += 2.0
    cap.modbus_stream(t0 + 0.05, HMI[0], PLC[0], hmi_polls, t1 - 0.5)
    cap.modbus_stream(t0 + 0.08, EWS[0], PLC[0], ews_polls, t1 - 0.4)


def attack(cap: OtCapture) -> None:
    # 305: the office PC (IT zone) opens Modbus to the PLC -> segmentation + unauthorized client
    cap.modbus_poll(305, OFFICE, PLC, reads=[(0, 10)])
    # 320: the office PC writes a holding register -> unauthorized write (critical)
    cap.modbus_poll(320, OFFICE, PLC, reads=[(0, 5)], writes=[(40, 9999)])
    # 335: a rogue device appears in the OT zone and ARP-sweeps
    for i, host in enumerate((PLC[0], EWS[0], HMI[0], OT_GW[0])):
        cap.arp(335 + i * 0.2, ROGUE_OT, host)
    # 350: the rogue polls the PLC over Modbus -> unauthorized client (OT zone, not allowlisted)
    cap.modbus_poll(350, ROGUE_OT, PLC, reads=[(0, 20)])
    # 365: the office PC floods the PLC with register reads -> abnormal Modbus rate
    cap.modbus_flood(365, OFFICE, PLC, n=150)
    # 380: a Telnet session is opened to the PLC -> unexpected protocol in OT
    cap.tcp_session(380, OFFICE[0], PLC[0], 23,
                    c2s=[Raw(b"root\r\n"), Raw(b"admin\r\n")], s2c=[Raw(b"login: "), Raw(b"Password: ")])
    # 395: the PLC dials an external host (C2) -> OT device communicating externally
    cap.tcp_session(395, PLC[0], C2, 443, c2s=[Raw(bytes(200))], s2c=[Raw(bytes(40))])


def build() -> list:
    cap = OtCapture()
    baseline(cap, 0, 300)
    baseline(cap, 300, 480)  # normal polling continues under the attack
    attack(cap)
    cap.packets.sort(key=lambda p: p.time)
    return cap.packets


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples" / "ot-lab.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    packets = build()
    wrpcap(str(out), packets)
    print(f"wrote {len(packets)} packets to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
