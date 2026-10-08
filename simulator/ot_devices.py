"""Simulated industrial (OT) devices for the lab, using Modbus/TCP over plain
sockets (no external dependency). ROLE selects the behaviour:

    plc     a PLC: a Modbus/TCP server on :502 holding 128 registers, driving
            a tiny simulated process (a motor RPM that drifts around a setpoint)
    ews     engineering workstation: reads the PLC and writes the setpoint
    hmi     HMI panel: reads the PLC for display

The attacker actions (unauthorized client, write, flood, Telnet, external) are
in attacks.py and injected by tools/ot_lab_scenarios.py, exactly as the IoT
lab injects its attacks. Nothing here reaches outside the lab.
"""

from __future__ import annotations

import os
import random
import socket
import struct
import threading
import time

PLC_IP = os.environ.get("PLC_IP", "192.168.10.20")
UNIT = 1
# register map: 0 = motor RPM (read), 40 = RPM setpoint (read/write)
REG_RPM, REG_SETPOINT = 0, 40


def mbap(txid: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, UNIT) + pdu


def recv_adu(sock: socket.socket) -> tuple[int, bytes] | None:
    head = _recvn(sock, 6)
    if not head:
        return None
    txid, _proto, length = struct.unpack(">HHH", head)
    body = _recvn(sock, length)
    if not body or len(body) < 2:
        return None
    return txid, body[1:]  # body = unit(1) + pdu


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# --------------------------------------------------------------------------- #
def run_plc() -> None:
    registers = [0] * 128
    registers[REG_SETPOINT] = 1450
    lock = threading.Lock()

    def process():  # the "physical" process: RPM wanders toward the setpoint
        while True:
            with lock:
                target = registers[REG_SETPOINT]
                registers[REG_RPM] = target + random.randint(-8, 8)
            time.sleep(1.0)

    threading.Thread(target=process, daemon=True).start()
    threading.Thread(target=_telnet_debug_port, daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 502))
    srv.listen(16)
    print("PLC: Modbus/TCP server on :502", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_serve, args=(conn, registers, lock), daemon=True).start()


def _telnet_debug_port() -> None:
    """Many real PLCs ship an open, forgotten Telnet debug port. The lab PLC
    does too, so DET-013 (unexpected protocol in OT) has something to find."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", 23))
        srv.listen(4)
    except OSError:
        return
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(b"PLC debug console\r\nlogin: ")
                conn.recv(64)
                conn.sendall(b"Password: ")
                conn.recv(64)
            except OSError:
                pass


def _serve(conn: socket.socket, registers: list[int], lock: threading.Lock) -> None:
    with conn:
        while True:
            try:
                msg = recv_adu(conn)
            except OSError:
                return
            if not msg:
                return
            txid, pdu = msg
            func = pdu[0]
            try:
                if func == 3:  # read holding registers
                    addr, qty = struct.unpack(">HH", pdu[1:5])
                    with lock:
                        data = b"".join(struct.pack(">H", registers[(addr + i) % 128] & 0xFFFF) for i in range(qty))
                    resp = struct.pack(">BB", 3, len(data)) + data
                elif func == 6:  # write single register
                    addr, value = struct.unpack(">HH", pdu[1:5])
                    with lock:
                        registers[addr % 128] = value
                    resp = struct.pack(">BHH", 6, addr, value)
                elif func == 16:  # write multiple registers
                    addr, qty = struct.unpack(">HH", pdu[1:5])
                    resp = struct.pack(">BHH", 16, addr, qty)
                else:
                    resp = struct.pack(">BB", func | 0x80, 1)  # illegal function
                conn.sendall(mbap(txid, resp))
            except (OSError, struct.error):
                return


def read_registers(sock: socket.socket, addr: int, qty: int, txid: int) -> None:
    sock.sendall(mbap(txid, struct.pack(">BHH", 3, addr, qty)))
    recv_adu(sock)


def write_register(sock: socket.socket, addr: int, value: int, txid: int) -> None:
    sock.sendall(mbap(txid, struct.pack(">BHH", 6, addr, value)))
    recv_adu(sock)


def run_client(write_setpoint: bool) -> None:
    """Engineering workstation (writes) or HMI (read-only): one long session."""
    txid = 0
    while True:
        try:
            with socket.create_connection((PLC_IP, 502), timeout=5) as sock:
                print(f"{'EWS' if write_setpoint else 'HMI'}: connected to PLC {PLC_IP}:502", flush=True)
                setpoint, last_write = 1450, time.time()
                while True:
                    txid = (txid + 1) & 0xFFFF
                    read_registers(sock, REG_RPM, 10, txid)
                    if write_setpoint and time.time() - last_write > 30:
                        setpoint += 5
                        write_register(sock, REG_SETPOINT, setpoint, txid)
                        last_write = time.time()
                    time.sleep(2.0)
        except OSError:
            time.sleep(2.0)  # PLC not up yet, or the session dropped: reconnect


def main() -> None:
    role = os.environ.get("ROLE", "plc")
    if role == "plc":
        run_plc()
    elif role == "ews":
        run_client(write_setpoint=True)
    elif role == "hmi":
        run_client(write_setpoint=False)
    else:
        raise SystemExit(f"unknown ROLE {role!r}")


if __name__ == "__main__":
    main()
