"""S7comm health probe.

Performs the COTP + S7comm setup handshake, then reads SZL 0x0424 (CPU
operating state) and SZL 0x00A0 (diagnostic buffer). Byte layouts match
sandbox/s7commplus_mock_server.py, which the tests run against.

Request layout the mock accepts:
  - COTP Connection Request  (frame byte 6 = 0xE0)      -> Connection Confirm
  - S7comm setup-communication (frame byte 9 ROSCTR=0x01) -> setup ack
  - SZL read (ROSCTR=0x07): 2-byte SZL-ID big-endian at frame bytes 30-31
    (0-based index 29-30).

Response layout the mock returns:
  - 0x0424: CPU state byte at the final byte of the frame.
  - 0x00A0: diag event id (big-endian u16) at the start of the trailing
    12-byte window (frame bytes 49-50); zeroed when no event is configured.
"""
import struct

from plchealth import faultcodes, framing
from plchealth.model import PLCHealth, Fault, State
from plchealth.probes import base

DEFAULT_PORT = 102

_COTP_CR = bytes.fromhex(
    "0300001611e00000000100c0010ac1020100c2020102")
_S7_SETUP = bytes.fromhex(
    "0300001902f08032010000000000080000f0000001000101e0")

_STATE_MAP = {
    "RUN": State.RUN, "STOP": State.STOP, "STARTUP": State.STARTUP,
    "HOLD": State.HOLD, "DEFECT": State.DEFECT,
}


def _read_tpkt(sock, timeout):
    head = framing.recv_exactly(sock, 4, timeout)
    total = struct.unpack(">H", head[2:4])[0]
    return head + framing.recv_exactly(sock, total - 4, timeout)


def _szl_request(szl_id):
    # S7 userdata SZL-read request. The mock dispatches on the 2-byte SZL-ID
    # (big-endian) at frame bytes 30-31 (S7 payload offset 22-23).
    s7 = bytearray(24)
    s7[0] = 0x32                                    # S7 protocol id
    s7[1] = 0x07                                    # ROSCTR: Userdata
    s7[22] = (szl_id >> 8) & 0xFF                   # SZL-ID high -> frame idx 29
    s7[23] = szl_id & 0xFF                          # SZL-ID low  -> frame idx 30
    payload = b"\x02\xf0\x80" + bytes(s7)           # COTP-DT header + S7
    tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(payload))
    return tpkt + payload


def probe(host, port=DEFAULT_PORT, timeout=3.0):
    try:
        with base.tcp(host, port, timeout) as sock:
            sock.sendall(_COTP_CR)
            _read_tpkt(sock, timeout)
            sock.sendall(_S7_SETUP)
            _read_tpkt(sock, timeout)

            sock.sendall(_szl_request(0x0424))
            state_resp = _read_tpkt(sock, timeout)
            cpu_byte = state_resp[-1]               # CPU state at last byte
            state_name = faultcodes.s7_cpu_state_name(cpu_byte)
            state = _STATE_MAP.get(state_name, State.UNKNOWN)

            sock.sendall(_szl_request(0x00A0))
            diag_resp = _read_tpkt(sock, timeout)
            faults = []
            tail = diag_resp[-12:]
            if len(tail) >= 2:
                event = struct.unpack(">H", tail[:2])[0]
                if event:
                    faults.append(Fault(
                        code=f"0x{event:04x}",
                        description=f"Diag buffer event 0x{event:04x}",
                        source="s7-diag", raw=framing.hexs(tail)))

            return PLCHealth(host=host, port=port, proto="s7", reachable=True,
                             state=state, faults=faults,
                             identity={"cpu_state": state_name},
                             raw=framing.hexs(state_resp))
    except OSError:
        return base.unreachable(host, port, "s7")
