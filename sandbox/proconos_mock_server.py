#!/usr/bin/env python3
"""
ProConOS PLC Honeypot Runtime Emulator

Emulates a ProConOS (KW-Software / Phoenix Contact) PLC runtime on TCP port 20547.
Supports multiple function codes, configurable device profiles, cyclic data exchange,
variable read/write, and blue-team detection logging.

Compatible with proconos-info-improved.nse for 0xCC identification probe.
Requirements: Python 3 stdlib only (no external dependencies).
"""

import socket
import struct
import threading
import argparse
import logging
import time
import sys
import random
from datetime import datetime

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger("proconos")

# ── Profile definitions ──────────────────────────────────────────────────────
# Variable entries: (name, type_code, value)
#   type_code: 0x01=BOOL, 0x02=INT, 0x03=DINT, 0x04=REAL, 0x05=STRING

PROFILES = {
    "adam5510kw": {
        "runtime":       "ProConOS V3.0.1040 Oct 29 2002",
        "plc_model":     "ADAM5510KW 1.24 Build 005",
        "project":       "510-projec",
        "boot_project":  "510-projec",
        "source_status": "Exist",
        "variables": {
            0: ("DigitalInput_0",  0x01, 1),
            1: ("DigitalInput_1",  0x01, 0),
            2: ("DigitalOutput_0", 0x01, 0),
            3: ("DigitalOutput_1", 0x01, 1),
            4: ("AnalogInput_0",   0x02, 512),
            5: ("AnalogInput_1",   0x02, 256),
            6: ("AnalogOutput_0",  0x02, 128),
            7: ("Counter_0",       0x03, 42),
            8: ("Timer_0",         0x04, 0.5),
            9: ("StatusStr",       0x05, "RUNNING"),
        },
    },
    "adam5510e": {
        "runtime":       "ProConOS V3.1.2050 Mar 15 2005",
        "plc_model":     "ADAM5510E 2.01 Build 012",
        "project":       "boiler-ctrl",
        "boot_project":  "boiler-ctrl",
        "source_status": "Exist",
        "variables": {
            0: ("BoilerTemp",    0x04, 185.5),
            1: ("BurnerState",   0x01, 1),
            2: ("Pressure",      0x04, 12.7),
            3: ("FlowRate",      0x04, 45.2),
            4: ("RuntimeHours",  0x03, 12345),
            5: ("WaterLevel",    0x04, 75.0),
            6: ("ValvePosition", 0x02, 50),
            7: ("AlarmActive",   0x01, 0),
            8: ("SetpointTemp",  0x04, 200.0),
            9: ("SystemMode",    0x05, "AUTO"),
        },
    },
    "adam5510m": {
        "runtime":       "ProConOS V3.2.3120 Nov 20 2008",
        "plc_model":     "ADAM5510M 3.00 Build 008",
        "project":       "turbine-mon",
        "boot_project":  "turbine-mon",
        "source_status": "Exist",
        "variables": {
            0: ("TurbineSpeed", 0x03, 3600),
            1: ("Vibration",    0x04, 0.05),
            2: ("OilTemp",      0x04, 65.3),
            3: ("BearingTemp",  0x04, 78.1),
            4: ("OutputPower",  0x04, 2500.0),
            5: ("BrakeApplied", 0x01, 0),
            6: ("OilPressure",  0x04, 3.5),
            7: ("RunHours",     0x03, 8765),
            8: ("FaultCode",    0x02, 0),
            9: ("TurbineState", 0x05, "ONLINE"),
        },
    },
    "generic": {
        "runtime":       "ProConOS V4.0.1000 Jan 10 2015",
        "plc_model":     "Generic PC Runtime 1.00",
        "project":       "generic-rtu",
        "boot_project":  "generic-rtu",
        "source_status": "Exist",
        "variables": {
            0: ("Input_0",    0x01, 0),
            1: ("Input_1",    0x01, 1),
            2: ("TempSensor", 0x04, 23.4),
            3: ("Counter",    0x03, 999),
            4: ("Setpoint",   0x04, 100.0),
            5: ("Output_0",   0x02, 0),
            6: ("Status",     0x05, "IDLE"),
            7: ("Humidity",   0x04, 45.0),
            8: ("Pressure",   0x04, 1013.25),
            9: ("CycleCount", 0x03, 5000),
        },
    },
}


# ── Variable serialisation helpers ───────────────────────────────────────────

def pack_var(type_code, value):
    """Pack a typed variable value into bytes."""
    if type_code == 0x01:  # BOOL
        return struct.pack("<B", 1 if value else 0)
    elif type_code == 0x02:  # INT (signed 16-bit)
        return struct.pack("<h", int(value))
    elif type_code == 0x03:  # DINT (signed 32-bit)
        return struct.pack("<i", int(value))
    elif type_code == 0x04:  # REAL (32-bit float)
        return struct.pack("<f", float(value))
    elif type_code == 0x05:  # STRING (null-terminated ASCII)
        s = str(value).encode("ascii", errors="replace") + b"\x00"
        return s
    return b"\x00"


def unpack_var(type_code, data, offset=0):
    """Unpack a typed variable from bytes at offset; returns (value, new_offset)."""
    if type_code == 0x01:
        return struct.unpack_from("<B", data, offset)[0], offset + 1
    elif type_code == 0x02:
        return struct.unpack_from("<h", data, offset)[0], offset + 2
    elif type_code == 0x03:
        return struct.unpack_from("<i", data, offset)[0], offset + 4
    elif type_code == 0x04:
        return struct.unpack_from("<f", data, offset)[0], offset + 4
    elif type_code == 0x05:
        end = data.find(b"\x00", offset)
        if end == -1:
            end = len(data)
        s = data[offset:end].decode("ascii", errors="replace")
        return s, end + 1
    return None, offset + 1


# ── Ident (0xCC) response builder ────────────────────────────────────────────
# Fixed-offset layout required by proconos-info-improved.nse:
#   offset  0: 0xCC
#   offset  1: header bytes (0x01 0x00 0x0b 0x00)
#   offset  5: 8 zero bytes
#   offset 13: runtime string (null-term)
#   offset 45: PLC model string (null-term)
#   offset 78: project name string (null-term)
#   after that: boot project, source status

def build_ident_response(profile):
    """Build 0xCC response compatible with NSE parser fixed-offset parsing."""
    buf = bytearray()
    buf.append(0xCC)
    buf.extend(b"\x01\x00\x0b\x00")
    buf.extend(b"\x00" * 8)
    while len(buf) < 13:
        buf.append(0x00)
    buf.extend(profile["runtime"].encode("ascii"))
    buf.append(0x00)
    while len(buf) < 45:
        buf.append(0x00)
    buf.extend(profile["plc_model"].encode("ascii"))
    buf.append(0x00)
    while len(buf) < 78:
        buf.append(0x00)
    buf.extend(profile["project"].encode("ascii"))
    buf.append(0x00)
    buf.extend(profile["boot_project"].encode("ascii"))
    buf.append(0x00)
    buf.extend(profile["source_status"].encode("ascii"))
    buf.append(0x00)
    buf.extend(b"\x00" * 16)
    return bytes(buf)


# ── Runtime status (0xF0) response builder ───────────────────────────────────

def build_runtime_status(state):
    """Pack runtime status: func + scan_cycles + uptime_sec + mem_pct + total_conns."""
    uptime = int(time.time() - state["start_time"])
    return struct.pack(
        "<Biiii", 0xF0, state["scan_cycles"], uptime,
        state["mem_usage"], state["total_connections"],
    )


# ── Cyclic data push builder ─────────────────────────────────────────────────

def build_cyclic_data(seq, variables):
    """
    Build a cyclic data push packet:
      [0x03][seq:u32][count:u16]{ [idx:u32][type:u8][value...] }...
    """
    buf = bytearray()
    buf.append(0x03)
    buf.extend(struct.pack("<I", seq))
    buf.extend(struct.pack("<H", len(variables)))
    for idx, (_name, tc, val) in sorted(variables.items()):
        buf.extend(struct.pack("<I", idx))
        buf.append(tc)
        buf.extend(pack_var(tc, val))
    return bytes(buf)


# ── Write audit tracker ──────────────────────────────────────────────────────

class WriteTracker:
    """Ring-buffer audit trail of variable write operations."""

    def __init__(self, maxlen=1000):
        self.writes = []
        self.maxlen = maxlen

    def log(self, client, idx, old_val, new_val):
        self.writes.append((time.time(), client, idx, old_val, new_val))
        while len(self.writes) > self.maxlen:
            self.writes.pop(0)

    def summary(self, n=5):
        return self.writes[-n:]


# ── Detection logging helper ─────────────────────────────────────────────────

FC_NAMES = {
    0xCC: "Ident/Discover",
    0x01: "Read Variable",
    0x02: "Write Variable",
    0x03: "Cyclic Start",
    0x04: "Cyclic Stop",
    0xF0: "Runtime Status",
}


def detection_log(client_addr, func_code, detail, hex_data="", verbose=False):
    """Log a structured detection event (always at WARNING level)."""
    fc_name = FC_NAMES.get(func_code, f"Unknown(0x{func_code:02x})")
    msg = (
        f"DETECT client={client_addr[0]}:{client_addr[1]} "
        f"fc=0x{func_code:02x}({fc_name}) {detail}"
    )
    if verbose and hex_data:
        limit = 200
        msg += f" hex={hex_data[:limit]}"
    log.warning(msg)


# ── recv_exactly helper (handles TCP fragmentation) ──────────────────────────

def recv_exactly(sock, size):
    """Read exactly *size* bytes; returns None on clean disconnect or error."""
    buf = b""
    while len(buf) < size:
        try:
            chunk = sock.recv(size - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# ── Per-connection variable state ────────────────────────────────────────────

class VarState:
    """Mutable variable snapshot for a single client connection."""

    def __init__(self, profile_name):
        pf = PROFILES[profile_name]
        self.vars = {k: list(v) for k, v in pf["variables"].items()}

    def get(self, idx):
        return self.vars.get(idx)

    def set(self, idx, value):
        v = self.vars.get(idx)
        if v is None:
            return False
        v[2] = value
        return True


# ── Function-code handlers ───────────────────────────────────────────────────

def _handle_cc(conn, addr, ident_resp, verbose):
    """0xCC — Ident / Discovery probe."""
    detection_log(addr, 0xCC, "ident/discovery probe", verbose=verbose)
    conn.sendall(ident_resp)


def _handle_read_var(conn, addr, state, payload, verbose):
    """0x01 — Read Variable by index."""
    if len(payload) < 4:
        detection_log(addr, 0x01, f"truncated payload ({len(payload)}b)")
        conn.sendall(bytes([0x01, 0xFF]))
        return

    idx = struct.unpack_from("<I", payload, 0)[0]
    var = state.get(idx)
    if var is None:
        detection_log(addr, 0x01, f"invalid index={idx}")
        conn.sendall(bytes([0x01, 0xFE]))
        return

    name, tc, val = var
    packed = pack_var(tc, val)
    resp = bytes([0x01, 0x00]) + struct.pack("<IB", idx, tc) + packed
    conn.sendall(resp)

    detection_log(
        addr, 0x01,
        f"idx={idx} name={name} type=0x{tc:02x} val={val}",
        verbose=verbose,
    )


def _handle_write_var(conn, addr, state, write_tracker, payload, verbose):
    """0x02 — Write Variable (honeypot: log but don't persist)."""
    if len(payload) < 5:
        detection_log(addr, 0x02, f"truncated payload ({len(payload)}b)")
        conn.sendall(bytes([0x02, 0xFF]))
        return

    idx = struct.unpack_from("<I", payload, 0)[0]
    tc = payload[4]
    val_bytes = payload[5:]

    var = state.get(idx)
    if var is None:
        detection_log(addr, 0x02, f"invalid index={idx}")
        conn.sendall(bytes([0x02, 0xFE]))
        return

    name, _existing_tc, old_val = var
    new_val, _ = unpack_var(tc, val_bytes)

    if new_val is not None:
        write_tracker.log(addr, idx, old_val, new_val)
        detection_log(
            addr, 0x02,
            f"idx={idx} name={name} {old_val} -> {new_val}",
            verbose=verbose,
        )
        conn.sendall(bytes([0x02, 0x00]))  # ACK
    else:
        detection_log(addr, 0x02, f"idx={idx} decode failed", verbose=verbose)
        conn.sendall(bytes([0x02, 0xFD]))  # decode error


def _handle_cyclic_start(conn, addr, state, cyclic_ev, cyclic_seq,
                         cyclic_lock, cycle_ms, verbose):
    """0x03 — Start cyclic data push (per-client thread)."""
    if cyclic_ev.is_set():
        detection_log(addr, 0x03, "duplicate start")
        conn.sendall(bytes([0x03, 0x01]))
        return

    cyclic_ev.set()
    cyclic_seq[0] = 0
    conn.sendall(bytes([0x03, 0x00]))  # ACK

    def _push_loop():
        while cyclic_ev.is_set():
            cyclic_seq[0] += 1
            with cyclic_lock:
                data = build_cyclic_data(cyclic_seq[0], state.vars)
            try:
                conn.sendall(data)
            except OSError:
                break
            time.sleep(cycle_ms / 1000.0)

    t = threading.Thread(target=_push_loop, daemon=True)
    t.start()

    detection_log(
        addr, 0x03,
        f"started interval={cycle_ms}ms",
        verbose=verbose,
    )


def _handle_cyclic_stop(conn, addr, cyclic_ev, verbose):
    """0x04 — Stop cyclic data push."""
    if cyclic_ev.is_set():
        cyclic_ev.clear()
        conn.sendall(bytes([0x04, 0x00]))  # ACK
        detection_log(addr, 0x04, "stopped", verbose=verbose)
    else:
        conn.sendall(bytes([0x04, 0x01]))


def _handle_runtime_status(conn, addr, rt_state, verbose):
    """0xF0 — Return runtime status (scan count, uptime, mem, connections)."""
    resp = build_runtime_status(rt_state)
    conn.sendall(resp)
    detection_log(
        addr, 0xF0,
        f"scans={rt_state['scan_cycles']} "
        f"uptime={int(time.time() - rt_state['start_time'])}s "
        f"conns={rt_state['total_connections']}",
        verbose=verbose,
    )


# ── Connection handler ───────────────────────────────────────────────────────

FRAMED_CODES = {0x01, 0x02, 0x03, 0x04, 0xF0}


def _drain_socket(conn):
    """Drain any residual data from the socket (non-blocking best-effort)."""
    conn.settimeout(0.05)
    try:
        while conn.recv(4096):
            pass
    except (socket.timeout, OSError):
        pass
    conn.settimeout(None)


def client_handler(conn, addr, profile_name, rt_state, write_tracker,
                   cycle_ms, verbose):
    """
    Per-connection request/response loop.

    Two protocol modes:
      * Legacy 0xCC probe — single-byte function code, response at fixed offsets.
      * Framed protocol    — [func(1)][len(2) LE][payload(len)] for fc in FRAMED_CODES.
    """
    cid = f"{addr[0]}:{addr[1]}"
    log.info(f"CONNECT {cid}")

    rt_state["total_connections"] += 1
    rt_state["current_connections"] += 1

    state = VarState(profile_name)
    ident_resp = build_ident_response(PROFILES[profile_name])

    # Cyclic data state
    cyclic_ev = threading.Event()
    cyclic_seq = [0]
    cyclic_lock = threading.Lock()

    try:
        while True:
            fc_byte = recv_exactly(conn, 1)
            if fc_byte is None:
                break
            func_code = fc_byte[0]

            # ── Legacy 0xCC probe (no framing) ──────────────────────────────────
            if func_code == 0xCC:
                rt_state["scan_cycles"] += 1
                # Drain residual probe data from the NSE probe
                _drain_socket(conn)
                _handle_cc(conn, addr, ident_resp, verbose)
                # NSE usually disconnects after receiving ident
                continue

            # ── Framed protocol: [func][len:u16 LE][payload] ─────────────────────
            if func_code not in FRAMED_CODES:
                detection_log(
                    addr, func_code,
                    f"unknown function code (not in {sorted(FRAMED_CODES)})",
                    verbose=verbose,
                )
                try:
                    conn.sendall(b"\x00")
                except OSError:
                    break
                continue

            len_bytes = recv_exactly(conn, 2)
            if len_bytes is None:
                break
            payload_len = struct.unpack("<H", len_bytes)[0]
            payload = recv_exactly(conn, payload_len) if payload_len else b""
            if payload_len and payload is None:
                break

            if func_code == 0x01:
                _handle_read_var(conn, addr, state, payload, verbose)
            elif func_code == 0x02:
                _handle_write_var(conn, addr, state, write_tracker, payload, verbose)
            elif func_code == 0x03:
                _handle_cyclic_start(conn, addr, state, cyclic_ev, cyclic_seq,
                                     cyclic_lock, cycle_ms, verbose)
            elif func_code == 0x04:
                _handle_cyclic_stop(conn, addr, cyclic_ev, verbose)
            elif func_code == 0xF0:
                rt_state["scan_cycles"] += 1
                _handle_runtime_status(conn, addr, rt_state, verbose)

    except ConnectionResetError:
        log.warning(f"RESET {cid}")
    except ConnectionAbortedError:
        log.warning(f"ABORT {cid}")
    except OSError as e:
        if verbose:
            log.debug(f"SOCKERR {cid}: {e}")
    except Exception as e:
        log.error(f"ERROR {cid}: {e}")
        if verbose:
            log.exception("Exception details")
    finally:
        if cyclic_ev.is_set():
            cyclic_ev.clear()
        rt_state["current_connections"] -= 1
        try:
            conn.close()
        except OSError:
            pass
        log.info(f"DISCONNECT {cid}")


# ── Server entry point ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ProConOS PLC Honeypot Runtime Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Available profiles:\n"
            "  adam5510kw  ADAM-5510KW, ProConOS V3.0.1040 Oct 29 2002\n"
            "  adam5510e   ADAM-5510E,  ProConOS V3.1.2050 Mar 15 2005\n"
            "  adam5510m   ADAM-5510M,  ProConOS V3.2.3120 Nov 20 2008\n"
            "  generic     PC-based,    ProConOS V4.0.1000 Jan 10 2015\n"
        ),
    )
    parser.add_argument("--port", type=int, default=20547,
                        help="TCP listen port (default: 20547)")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--profile", type=str, default="adam5510kw",
                        choices=sorted(PROFILES.keys()),
                        help="PLC device profile (default: adam5510kw)")
    parser.add_argument("--cycle-ms", type=int, default=1000,
                        help="Cyclic data push interval in ms (default: 1000)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug("Verbose logging enabled")

    pf = PROFILES[args.profile]

    # Shared runtime counters (thread-safe: increment-only ints)
    rt_state = {
        "start_time": time.time(),
        "scan_cycles": 0,
        "total_connections": 0,
        "current_connections": 0,
        "mem_usage": random.randint(35, 55),
    }
    write_tracker = WriteTracker()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(10)

    log.info("─" * 52)
    log.info(f"ProConOS Honeypot starting on {args.host}:{args.port}")
    log.info(f"Profile:          {args.profile}")
    log.info(f"  Runtime:        {pf['runtime']}")
    log.info(f"  PLC Model:      {pf['plc_model']}")
    log.info(f"  Project:        {pf['project']}")
    log.info(f"  Variables:      {len(pf['variables'])}")
    log.info(f"Cyclic interval:  {args.cycle_ms} ms")
    log.info("─" * 52)
    log.info("Press Ctrl+C to stop")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(
                target=client_handler,
                args=(conn, addr, args.profile, rt_state,
                      write_tracker, args.cycle_ms, args.verbose),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt — shutting down...")
    finally:
        n_conns = rt_state["total_connections"]
        n_writes = len(write_tracker.writes)
        log.info(f"Server stopped after {n_conns} connection(s).")
        log.info(f"Write events tracked: {n_writes}")
        if write_tracker.writes:
            log.info("Last 5 write events:")
            for ts, client, idx, old, new in write_tracker.summary(5):
                log.info(
                    f"  [{datetime.fromtimestamp(ts).isoformat()}] "
                    f"{client} var[{idx}] {old} -> {new}"
                )
        server.close()


if __name__ == "__main__":
    main()
