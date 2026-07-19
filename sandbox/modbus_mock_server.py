#!/usr/bin/env python3
"""
Minimal Modbus TCP mock for plchealth tests.

Serves Read Holding Registers (function 0x03). Two knobs let a test present a
faulted PLC:
  --fault-reg-value N   value returned for the status register (default 0)
  --exception CODE      instead of data, reply with a Modbus exception

Usage:
    python3 modbus_mock_server.py --port 15020
    python3 modbus_mock_server.py --port 15020 --fault-reg-value 1
    python3 modbus_mock_server.py --port 15020 --exception 4
    python3 modbus_mock_server.py --self-test
"""
import argparse
import socketserver
import struct


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(512)
        if len(data) < 12:
            return
        txn, proto, length, unit, func = struct.unpack(">HHHBB", data[:8])
        cfg = self.server.cfg
        if func == 0x03:
            if cfg.exception is not None:
                pdu = struct.pack(">BB", 0x03 | 0x80, cfg.exception)
            else:
                start, qty = struct.unpack(">HH", data[8:12])
                regs = [cfg.fault_reg_value] + [0] * (qty - 1)
                body = b"".join(struct.pack(">H", r) for r in regs[:qty])
                pdu = struct.pack(">BB", 0x03, len(body)) + body
            resp = struct.pack(">HHHB", txn, 0, len(pdu) + 1, unit) + pdu
            self.request.sendall(resp)


def build_response(func, txn, unit, fault_reg_value=0, exception=None, qty=1):
    """Pure helper the self-test uses to verify framing without sockets."""
    if exception is not None:
        pdu = struct.pack(">BB", func | 0x80, exception)
    else:
        regs = [fault_reg_value] + [0] * (qty - 1)
        body = b"".join(struct.pack(">H", r) for r in regs[:qty])
        pdu = struct.pack(">BB", func, len(body)) + body
    return struct.pack(">HHHB", txn, 0, len(pdu) + 1, unit) + pdu


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15020)
    ap.add_argument("--fault-reg-value", type=int, default=0)
    ap.add_argument("--exception", type=int, default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        r = build_response(0x03, 1, 1, fault_reg_value=1)
        assert r[7] == 0x03 and r[-1] == 1, r.hex()
        e = build_response(0x03, 1, 1, exception=4)
        assert e[7] == 0x83 and e[8] == 4, e.hex()
        print("self-test OK")
        return

    # allow_reuse_address so the test harness can rebind a port still in
    # TIME_WAIT from a prior run without the bind crashing the mock.
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(("127.0.0.1", args.port), Handler)
    server.cfg = args
    server.serve_forever()


if __name__ == "__main__":
    main()
