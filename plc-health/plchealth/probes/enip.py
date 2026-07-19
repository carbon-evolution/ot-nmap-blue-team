"""EtherNet/IP (CIP) health probe via the ListIdentity command.

Parses the Identity CPF item's status word and state byte and maps CIP fault
bits to faults. A faulted state byte or any fault bit => FAULT.
"""
import struct

from plchealth import faultcodes, framing
from plchealth.model import PLCHealth, Fault, State
from plchealth.probes import base

DEFAULT_PORT = 44818


def _list_identity_request():
    # 24-byte encapsulation header, command 0x0063, all else zero.
    return struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)


def probe(host, port=DEFAULT_PORT, timeout=3.0):
    try:
        with base.tcp(host, port, timeout) as sock:
            sock.sendall(_list_identity_request())
            header = framing.recv_exactly(sock, 24, timeout)
            (_cmd, length) = struct.unpack("<HH", header[:4])
            body = framing.recv_exactly(sock, length, timeout)
            # body: item count (u16), then CPF item: type(u16) len(u16) data
            item_len = struct.unpack("<H", body[4:6])[0]
            item = body[6:6 + item_len]
            # Identity body: status word at [26:28] LE, state = last byte.
            status = struct.unpack("<H", item[26:28])[0]
            state_byte = item[-1]

            faults = [Fault(code=f"0x{status:04x}", description=d, source="cip")
                      for d in faultcodes.cip_status_faults(status)]
            state_name = faultcodes.cip_state_name(state_byte)
            state = State.RUN
            if state_byte == 2 or faults:
                state = State.FAULT
            elif state_byte in (3, 1):
                state = State.STOP
            return PLCHealth(host=host, port=port, proto="enip",
                             reachable=True, state=state, faults=faults,
                             identity={"status": status, "state": state_byte,
                                       "state_name": state_name},
                             raw=framing.hexs(item))
    except OSError:
        return base.unreachable(host, port, "enip")
