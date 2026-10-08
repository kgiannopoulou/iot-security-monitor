"""Modbus/TCP visibility: who talks to the PLCs, and what they ask for.

Modbus is the most common industrial (OT) protocol. A client (an
engineering workstation or HMI) opens a TCP session to a PLC on port 502
and sends requests that read or write the PLC's registers and coils, the
numbers that drive the physical process. There is no authentication.

Each Modbus/TCP message is an MBAP header followed by a PDU:

    transaction(2) protocol(2)=0 length(2) unit(1) | function(1) data...

`parse_modbus` turns a TCP payload into a list of decoded PDUs (one segment
can carry several). The `ModbusTracker` turns those into per-session facts:
which client talks to which PLC, the function codes it uses, whether it
writes, and the register ranges it touches. DET-010..015 read that.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import PacketRecord

MODBUS_PORT = 502

# function code -> (name, writes state?)
FUNCTIONS: dict[int, tuple[str, bool]] = {
    1: ("Read Coils", False),
    2: ("Read Discrete Inputs", False),
    3: ("Read Holding Registers", False),
    4: ("Read Input Registers", False),
    5: ("Write Single Coil", True),
    6: ("Write Single Register", True),
    7: ("Read Exception Status", False),
    8: ("Diagnostics", False),
    11: ("Get Comm Event Counter", False),
    12: ("Get Comm Event Log", False),
    15: ("Write Multiple Coils", True),
    16: ("Write Multiple Registers", True),
    17: ("Report Server ID", False),
    20: ("Read File Record", False),
    21: ("Write File Record", True),
    22: ("Mask Write Register", True),
    23: ("Read/Write Multiple Registers", True),
    43: ("Read Device Identification", False),
}


def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


def parse_modbus(payload: bytes, to_server: bool) -> list[dict]:
    """Decode the Modbus ADUs in one TCP payload.

    `to_server` (destination port 502) means these are requests, which is
    when the address and quantity fields are at a known offset.
    """
    pdus: list[dict] = []
    i, n = 0, len(payload)
    while i + 8 <= n:
        if _u16(payload, i + 2) != 0:  # protocol identifier must be 0 for Modbus
            break
        length = _u16(payload, i + 4)  # bytes following the length field (unit + PDU)
        if length < 2 or i + 6 + length > n:
            break
        unit = payload[i + 6]
        func = payload[i + 7]
        pdu = payload[i + 8: i + 6 + length]
        exception = bool(func & 0x80)
        base = func & 0x7F
        name, writes = FUNCTIONS.get(base, (f"function {base}", False))
        rec = {"unit": unit, "func": base, "name": name, "write": writes and not exception,
               "exception": exception, "request": to_server}
        if exception and pdu:
            rec["exception_code"] = pdu[0]
        elif to_server and base in (1, 2, 3, 4, 5, 6) and len(pdu) >= 4:
            rec["address"] = _u16(pdu, 0)
            rec["quantity"] = 1 if base in (5, 6) else _u16(pdu, 2)
        elif to_server and base in (15, 16) and len(pdu) >= 4:
            rec["address"] = _u16(pdu, 0)
            rec["quantity"] = _u16(pdu, 2)
        pdus.append(rec)
        i += 6 + length
    return pdus


@dataclass(slots=True)
class ModbusConversation:
    """One client → PLC Modbus relationship (keyed by the two IPs)."""
    client: str
    server: str
    first_seen: float
    last_seen: float
    requests: int = 0
    responses: int = 0
    exceptions: int = 0
    writes: int = 0
    functions: set = field(default_factory=set)   # function names seen from the client
    units: set = field(default_factory=set)        # unit IDs addressed
    read_registers: set = field(default_factory=set)
    write_registers: set = field(default_factory=set)

    def as_dict(self) -> dict:
        def span(regs: set) -> str:
            return "" if not regs else f"{min(regs)}-{max(regs)}" if len(regs) > 1 else str(min(regs))
        return {"client": self.client, "server": self.server, "first_seen": self.first_seen,
                "last_seen": self.last_seen, "requests": self.requests, "responses": self.responses,
                "exceptions": self.exceptions, "writes": self.writes,
                "functions": ",".join(sorted(self.functions)), "units": ",".join(str(u) for u in sorted(self.units)),
                "read_registers": span(self.read_registers), "write_registers": span(self.write_registers)}


@dataclass(slots=True)
class ModbusEvent:
    kind: str           # request | response
    client: str
    server: str
    unit: int
    func: int
    name: str
    write: bool
    exception: bool
    address: int | None = None
    quantity: int | None = None
    first_request: bool = False   # first time this client spoke Modbus to this server


class ModbusTracker:
    """Broker-style view of Modbus/TCP: conversations keyed by (client, server)."""

    def __init__(self):
        self.conversations: dict[tuple[str, str], ModbusConversation] = {}
        self.servers: set[str] = set()   # IPs seen answering on port 502 (the PLCs)
        self.events: list[ModbusEvent] = []

    def update(self, rec: PacketRecord) -> list[ModbusEvent]:
        self.events = []
        pdus = rec.meta.get("modbus")
        if not pdus or rec.protocol != "TCP":
            return self.events
        to_server = rec.dport == MODBUS_PORT
        if to_server:
            client, server = rec.src_ip, rec.dst_ip
        else:
            client, server = rec.dst_ip, rec.src_ip
            self.servers.add(server)
        if not client or not server:
            return self.events
        key = (client, server)
        conv = self.conversations.get(key)
        first = conv is None
        if conv is None:
            conv = self.conversations[key] = ModbusConversation(client, server, rec.ts, rec.ts)
        conv.last_seen = rec.ts

        for pdu in pdus:
            conv.units.add(pdu["unit"])
            if pdu["request"]:
                conv.requests += 1
                conv.functions.add(pdu["name"])
                if pdu["write"]:
                    conv.writes += 1
                if "address" in pdu and "quantity" in pdu:
                    regs = range(pdu["address"], pdu["address"] + max(pdu["quantity"], 1))
                    (conv.write_registers if pdu["write"] else conv.read_registers).update(regs)
            else:
                conv.responses += 1
                if pdu["exception"]:
                    conv.exceptions += 1
            self.events.append(ModbusEvent(
                "request" if pdu["request"] else "response", client, server, pdu["unit"], pdu["func"],
                pdu["name"], pdu["write"], pdu["exception"], pdu.get("address"), pdu.get("quantity"),
                first_request=first and pdu["request"]))
            first = False
        return self.events
