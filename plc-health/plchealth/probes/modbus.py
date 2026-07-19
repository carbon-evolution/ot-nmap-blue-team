"""Modbus TCP health probe.

Modbus has no CPU RUN/STOP concept. Health is inferred from:
  - connectivity (unreachable => UNREACHABLE),
  - a Modbus exception response => FAULT,
  - a configurable status/fault register bit => FAULT.
Otherwise RUN.
"""
import struct

from plchealth import faultcodes, framing
from plchealth.model import PLCHealth, Fault, State
from plchealth.probes import base

DEFAULT_PORT = 502


def _read_holding(sock, unit, start, qty, timeout):
    req = struct.pack(">HHHBBHH", 1, 0, 6, unit, 0x03, start, qty)
    sock.sendall(req)
    header = framing.recv_exactly(sock, 8, timeout)  # MBAP(7)+function(1)
    _, _, length, _, func = struct.unpack(">HHHBB", header)
    rest = framing.recv_exactly(sock, length - 2, timeout)  # remaining PDU
    return func, rest


def probe(host, port=DEFAULT_PORT, timeout=3.0, unit=1,
          status_reg=0, fault_bit=None):
    try:
        with base.tcp(host, port, timeout) as sock:
            func, rest = _read_holding(sock, unit, status_reg, 1, timeout)
            if func & 0x80:
                code = rest[0]
                fault = Fault(code=f"0x{code:02x}",
                              description=faultcodes.modbus_exception_name(code),
                              source="modbus", raw=framing.hexs(rest))
                return PLCHealth(host=host, port=port, proto="modbus",
                                 reachable=True, state=State.FAULT, faults=[fault],
                                 raw=framing.hexs(rest))
            byte_count = rest[0]
            regval = struct.unpack(">H", rest[1:3])[0] if byte_count >= 2 else 0
            faults = []
            state = State.RUN
            if fault_bit is not None and (regval >> fault_bit) & 1:
                faults.append(Fault(code=f"reg{status_reg}.bit{fault_bit}",
                                    description="PLC fault bit set",
                                    source="modbus", raw=f"{regval:#06x}"))
                state = State.FAULT
            return PLCHealth(host=host, port=port, proto="modbus",
                             reachable=True, state=state, faults=faults,
                             identity={"status_reg": regval},
                             raw=framing.hexs(rest))
    except OSError:
        return base.unreachable(host, port, "modbus")
