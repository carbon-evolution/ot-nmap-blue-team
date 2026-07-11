#!/usr/bin/env python3
"""
MELSEC-Q PLC Honeypot — TCP 5007.

Realistic emulation of a Mitsubishi MELSEC-Q Series PLC with MC protocol
3E-frame (binary mode) support.  Handles multiple subheader types for
device discovery, batch reads, batch writes, and loop-back testing.

Subheaders:
  0x5000  — 3E binary mode (standard command/subcommand dispatch).
            Used by NSE scripts (melsecq-info-improved.nse) for CPU type,
            model name, and firmware version queries.
  0x0401  — Device read batch (D-registers / M-coils / X / Y).
  0x1401  — Device write batch (accepted but not persisted).
  0x0500  — Loop test (echo-back with increment).

Wire compatibility is maintained for melsecq-info-improved.nse on the
0x5000 subheader path.

References:
  - MELSEC Communication Protocol Reference Manual (SH-080008)
  - MELSEC-Q/L Programming Manual (Mitsubishi Electric)
"""

import argparse
import logging
import random
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("melsecq")


# ---------------------------------------------------------------------------
# MC Protocol constants
# ---------------------------------------------------------------------------

# Error codes (16-bit LE)
ERR_SUCCESS          = 0x0000
ERR_ILLEGAL_CMD      = 0xC051
ERR_ILLEGAL_SUBCMD   = 0xC052
ERR_ILLEGAL_DEVICE   = 0xC054
ERR_ILLEGAL_ADDRESS  = 0xC055
ERR_ILLEGAL_LENGTH   = 0xC059
ERR_RW_SIZE          = 0xC05B

# Subheader identifiers
SUBHDR_5000  = 0x5000   # 3E binary mode (NSE-compatible)
SUBHDR_0401  = 0x0401   # Device read batch
SUBHDR_1401  = 0x1401   # Device write batch
SUBHDR_0500  = 0x0500   # Loop test

# Commands inside subheader 0x5000
CMD_CPU_TYPE = 0x0101
CMD_MODEL    = 0x0100
CMD_VERSION  = 0x0113

# Device codes for batch read/write
DEV_D = 0x44   # Data register (D)  — word device, 16-bit
DEV_M = 0x4D   # Internal relay (M) — bit device
DEV_X = 0x58   # Input (X)          — bit device
DEV_Y = 0x59   # Output (Y)         — bit device

# Bit-device set for quick lookup
BIT_DEVICES = {DEV_M, DEV_X, DEV_Y}

# ---------------------------------------------------------------------------
# Device profiles
# ---------------------------------------------------------------------------
PROFILES = {
    "q03udvcpu": {"cpu_type": "Q03UDVCPU", "firmware": "1.20"},
    "q06udvcpu": {"cpu_type": "Q06UDVCPU", "firmware": "2.10"},
    "q13udvcpu": {"cpu_type": "Q13UDVCPU", "firmware": "1.50"},
    "q26udvcpu": {"cpu_type": "Q26UDVCPU", "firmware": "3.00"},
}

MODEL_STR = "MELSEC-Q Series"   # returned by model-name read (0x0100)


# ---------------------------------------------------------------------------
# Simulated process values
# ---------------------------------------------------------------------------
# D-register addresses mapped to base (integer) values.  Each read applies
# a small random jitter so the honeypot feels like a live process.
#
# Values use fixed-point scaling (×10) for one-decimal resolution:
#   e.g. 250  → 25.0 °C  ;  1000 → 100.0 kPa.

_SIMULATED_D = {
    # Temperatures (°C ×10)
    100:  250,    101:  251,    102:  248,    103:  252,
    # Pressures (kPa ×10)
    200: 1000,    201: 1005,    202:  998,
    # Speeds (RPM)
    300: 1500,    301: 1498,    302: 1502,
    # Flow rates (L/min ×10)
    400: 5000,    401: 4995,
}


def init_simulated():
    """(Re)seed the simulated D-register dictionary."""
    pass  # _SIMULATED_D is already populated


def get_simulated_d(addr: int) -> int:
    """Return a D-register value with ±3-digit jitter (simulating live I/O)."""
    base = _SIMULATED_D.get(addr, random.randint(0, 100))
    return base + random.randint(-3, 3)


# ---------------------------------------------------------------------------
# Binary packing helpers
# ---------------------------------------------------------------------------

# LE helpers (for commands, subcommands, data-length fields, error codes)
def pack_u16(val: int) -> bytes:
    """uint16 → 2 bytes LE."""
    return struct.pack("<H", val)


def pack_u24(val: int) -> bytes:
    """uint24 → 3 bytes LE."""
    return bytes([val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF])


def unpack_u16(data: bytes, offset: int) -> int:
    """2 bytes LE → uint16."""
    return struct.unpack_from("<H", data, offset)[0]


def unpack_u24(data: bytes, offset: int) -> int:
    """3 bytes LE → uint24."""
    return data[offset] + (data[offset + 1] << 8) + (data[offset + 2] << 16)


# BE helpers (for subheader field only — MC protocol uses BE for subheader)
def pack_u16_be(val: int) -> bytes:
    """uint16 → 2 bytes big-endian."""
    return bytes([(val >> 8) & 0xFF, val & 0xFF])


def unpack_u16_be(data: bytes, offset: int) -> int:
    """2 bytes big-endian → uint16."""
    return (data[offset] << 8) | data[offset + 1]


# ---------------------------------------------------------------------------
# Frame parsers
# ---------------------------------------------------------------------------

def parse_3e_5000(data: bytes):
    """Parse a subheader=0x5000 3E binary-mode request.

    Frame layout (0x5000 / NSE-compatible):
      [subhdr 2][net 1][pc 1][io 2][station 1][dlen 3][timer 3][cmd 2][subcmd 2][data…]

    Returns (network, pc, io_bytes, station, command, subcommand, payload)
    or raises ValueError.
    """
    if len(data) < 17:
        raise ValueError(f"0x5000 frame too short: {len(data)} bytes")

    if unpack_u16_be(data, 0) != SUBHDR_5000:
        raise ValueError(f"Not a 0x5000 subheader: 0x{unpack_u16_be(data, 0):04x}")

    network = data[2]
    pc      = data[3]
    io      = data[4:6]
    station = data[6]
    dlen    = unpack_u24(data, 7)

    if len(data) < 10 + dlen:
        raise ValueError(f"0x5000 frame truncated: {10 + dlen} expected, got {len(data)}")

    payload = data[10:10 + dlen]
    if len(payload) < 7:      # timer(3) + cmd(2) + subcmd(2)
        raise ValueError(f"0x5000 payload too short: {len(payload)} bytes")

    cmd    = unpack_u16(payload, 3)
    subcmd = unpack_u16(payload, 5)
    pldata = payload[7:]

    return network, pc, io, station, cmd, subcmd, pldata


def parse_extended_frame(data: bytes):
    """Parse a non-0x5000 extended 3E frame.

    Frame layout (extended):
      [subhdr 2][network 2][unit 1][dest 2][src 2][timer 2][dlen 2][end 1][data…]

    Returns (subhdr, network, unit, dest, src, timer_bytes, end_flag, payload)
    or raises ValueError.
    """
    HDR_SZ = 2 + 2 + 1 + 2 + 2 + 2 + 2 + 1   # = 14
    if len(data) < HDR_SZ:
        raise ValueError(f"Extended frame too short: {len(data)} bytes")

    subhdr  = unpack_u16_be(data, 0)
    network = unpack_u16(data, 2)
    unit    = data[4]
    dest    = unpack_u16(data, 5)
    src     = unpack_u16(data, 7)
    timer   = data[9:11]     # 2-byte monitoring timer
    dlen    = unpack_u16(data, 11)
    end_    = data[13]

    if len(data) < HDR_SZ + dlen:
        raise ValueError(f"Extended frame truncated: hdr({HDR_SZ}) + dlen({dlen}) > {len(data)}")

    payload = data[14:14 + dlen]

    return subhdr, network, unit, dest, src, timer, end_, payload


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------

def build_3e_5000_resp(network: int, pc: int, io: bytes, station: int,
                       response_data: bytes) -> bytes:
    """Build a 0x5000 response frame with success code + data."""
    payload = pack_u16(ERR_SUCCESS) + response_data
    return (
        pack_u16_be(0xD000)          # BE: MC protocol subheader
        + bytes([network])
        + bytes([pc])
        + io
        + bytes([station])
        + pack_u24(len(payload))
        + payload
    )


def build_3e_5000_err(network: int, pc: int, io: bytes, station: int,
                      err_code: int) -> bytes:
    """Build a 0x5000 error response (error code only)."""
    payload = pack_u16(err_code)
    return (
        pack_u16_be(0xD000)          # BE: MC protocol subheader
        + bytes([network])
        + bytes([pc])
        + io
        + bytes([station])
        + pack_u24(len(payload))
        + payload
    )


def build_ext_resp(subhdr: int, network: int, unit: int, dest: int,
                   src: int, response_data: bytes) -> bytes:
    """Build an extended-frame response with success + data."""
    payload = pack_u16(ERR_SUCCESS) + response_data
    dlen = len(payload)
    return (
        pack_u16_be(subhdr | 0x8000)  # BE: MC protocol subheader
        + pack_u16(network)
        + bytes([unit])
        + pack_u16(dest)
        + pack_u16(src)               # incremented sequence
        + b"\x00\x10"                 # timer (1000 ms)
        + pack_u16(dlen)
        + b"\x00"                     # end flag
        + payload
    )


def build_ext_err(subhdr: int, network: int, unit: int, dest: int,
                  src: int, err_code: int) -> bytes:
    """Build an extended-frame error response."""
    payload = pack_u16(err_code)
    return (
        pack_u16_be(subhdr | 0x8000)  # BE: MC protocol subheader
        + pack_u16(network)
        + bytes([unit])
        + pack_u16(dest)
        + pack_u16(src)
        + b"\x00\x10"
        + pack_u16(2)                 # dlen = 2 (error code)
        + b"\x00"
        + payload
    )


# ---------------------------------------------------------------------------
# 0x5000 subheader command handlers
# ---------------------------------------------------------------------------

def handle_cpu_type_read(network, pc, io, station, profile):
    cpu = profile["cpu_type"]
    log.info("  → CPU type read: %s", cpu)
    data = cpu.encode("ascii").ljust(16, b"\x00")
    return build_3e_5000_resp(network, pc, io, station, data)


def handle_model_read(network, pc, io, station):
    log.info("  → Model read: %s", MODEL_STR)
    data = MODEL_STR.encode("ascii").ljust(16, b"\x00")
    return build_3e_5000_resp(network, pc, io, station, data)


def handle_version_read(network, pc, io, station, profile):
    ver = profile["firmware"]
    log.info("  → Version read: %s", ver)
    data = ver.encode("ascii").ljust(16, b"\x00")
    return build_3e_5000_resp(network, pc, io, station, data)


# Command dispatch table (cmd -> handler)
CMD_HANDLERS_5000 = {
    CMD_CPU_TYPE: lambda n, p, i, s, prof: handle_cpu_type_read(n, p, i, s, prof),
    CMD_MODEL:    lambda n, p, i, s, prof: handle_model_read(n, p, i, s),
    CMD_VERSION:  lambda n, p, i, s, prof: handle_version_read(n, p, i, s, prof),
}


# ---------------------------------------------------------------------------
# Extended subheader handlers (0x0401, 0x1401, 0x0500)
# ---------------------------------------------------------------------------

def handle_device_read(subhdr, network, unit, dest, src, payload, verbose):
    """Device read batch (0x0401).

    Request data:  [dev_code 1B][start_addr 3B LE][points 2B LE]
    Response:      success + N×value bytes
    """
    if len(payload) < 6:
        return build_ext_err(subhdr, network, unit, dest, src, ERR_ILLEGAL_LENGTH)

    dev_code   = payload[0]
    start_addr = unpack_u24(payload, 1)
    points     = unpack_u16(payload, 4)

    if verbose:
        log.info("  → Device read: code=0x%02x addr=%d count=%d",
                 dev_code, start_addr, points)

    if points == 0 or points > 256:
        return build_ext_err(subhdr, network, unit, dest, src, ERR_ILLEGAL_LENGTH)

    if dev_code in BIT_DEVICES:
        # Bit devices: 1 byte per point (0x00 or 0x01)
        data = bytes([random.randint(0, 1) for _ in range(points)])
        return build_ext_resp(subhdr, network, unit, dest, src, data)

    if dev_code == DEV_D:
        # D-registers: 2 bytes per point (16-bit LE)
        data = b"".join(pack_u16(get_simulated_d(start_addr + i) & 0xFFFF)
                        for i in range(points))
        return build_ext_resp(subhdr, network, unit, dest, src, data)

    log.warning("  → Unknown device code: 0x%02x", dev_code)
    return build_ext_err(subhdr, network, unit, dest, src, ERR_ILLEGAL_DEVICE)


def handle_device_write(subhdr, network, unit, dest, src, payload, verbose):
    """Device write batch (0x1401).

    Request data:  [dev_code 1B][start_addr 3B LE][write_values…]
    Response:      success (empty data) — writes are accepted but not persisted.
    """
    if len(payload) < 4:
        return build_ext_err(subhdr, network, unit, dest, src, ERR_ILLEGAL_LENGTH)

    dev_code   = payload[0]
    start_addr = unpack_u24(payload, 1)
    write_len  = len(payload) - 4

    if verbose:
        log.info("  → Device write: code=0x%02x addr=%d len=%d (accepted)",
                 dev_code, start_addr, write_len)

    # Accept without persisting — pure stateless honeypot
    return build_ext_resp(subhdr, network, unit, dest, src, b"")


def handle_loop_test(subhdr, network, unit, dest, src, payload, verbose):
    """Loop test (0x0500) — echo payload back with first 2 bytes incremented."""
    if len(payload) >= 2:
        first = unpack_u16(payload, 0)
        echoed = pack_u16((first + 1) & 0xFFFF) + payload[2:]
    else:
        echoed = payload  # too short to increment; echo as-is

    if verbose:
        log.info("  → Loop test: echoed %d bytes", len(echoed))

    return build_ext_resp(subhdr, network, unit, dest, src, echoed)


# Extended subheader dispatch
EXT_HANDLERS = {
    SUBHDR_0401: handle_device_read,
    SUBHDR_1401: handle_device_write,
    SUBHDR_0500: handle_loop_test,
}


# ---------------------------------------------------------------------------
# recv helper
# ---------------------------------------------------------------------------

def recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly *n* bytes from *sock*, or return None on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Detection-logging helpers
# ---------------------------------------------------------------------------

def detection_event(addr, direction: str, summary: str, hex_data: str = ""):
    """Emit a detection-log line with timestamp and client identity."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    base = f"DETECT|{now}|{addr[0]}:{addr[1]}|{direction}|{summary}"
    if hex_data:
        base += f"|hex:{hex_data[:128]}"
    log.warning("%s", base)


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def handle_client(conn, addr, profile, scan_delay, verbose):
    """Service a single TCP connection (potentially multiple requests)."""
    detection_event(addr, "OPEN", "Connection established")
    last_seq = -1  # sequence-number tracker (extended frames)

    try:
        conn.settimeout(30.0)

        while True:
            # ---------------------------------------------------------------
            # Phase 1 — read the fixed-size header prefix
            # ---------------------------------------------------------------
            # Minimum bytes needed to determine frame type + data length:
            #   - 0x5000 format: 10 bytes (hdr 7 + dlen 3)
            #   - Extended:      14 bytes (full extended header)
            # We read 14 bytes up-front, which covers both.
            header = recv_exactly(conn, 14)
            if header is None:
                log.info("Client %s closed connection", addr[0])
                detection_event(addr, "CLOSE", "EOF")
                break

            # ---------------------------------------------------------------
            # Phase 2 — determine frame format and total length
            # ---------------------------------------------------------------
            subhdr = unpack_u16_be(header, 0)

            if subhdr == SUBHDR_5000:
                # Old 0x5000 format: dlen at header offset 7 (3 bytes LE)
                dlen = unpack_u24(header, 7)
                total = 10 + dlen      # hdr(7) + dlen(3) + body(dlen)
            else:
                # Extended format: dlen at header offset 11 (2 bytes LE)
                dlen = unpack_u16(header, 11)
                total = 14 + dlen

            # ---------------------------------------------------------------
            # Phase 3 — read any remaining frame bytes
            # ---------------------------------------------------------------
            if total > 14:
                rest = recv_exactly(conn, total - 14)
                if rest is None:
                    log.info("Client %s disconnected mid-frame", addr[0])
                    detection_event(addr, "ERROR", "Mid-frame disconnect")
                    break
                frame = header + rest
            else:
                frame = header[:total]

            # ---------------------------------------------------------------
            # Phase 4 — parse and handle
            # ---------------------------------------------------------------
            hex_dump = frame.hex() if verbose else ""
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            try:
                if subhdr == SUBHDR_5000:
                    network, pc, io, station, cmd, subcmd, pldata = \
                        parse_3e_5000(frame)

                    summary = f"subhdr=0x{SUBHDR_5000:04x} cmd=0x{cmd:04x} sc=0x{subcmd:04x}"
                    log.info("[%s] %s:%d %s", ts, addr[0], addr[1], summary)
                    detection_event(addr, "REQ", summary, hex_dump)

                    handler = CMD_HANDLERS_5000.get(cmd)
                    if handler:
                        resp = handler(network, pc, io, station, profile)
                        err = ERR_SUCCESS
                    else:
                        log.warning("  → Unknown cmd=0x%04x", cmd)
                        resp = build_3e_5000_err(network, pc, io, station,
                                                  ERR_ILLEGAL_CMD)
                        err = ERR_ILLEGAL_CMD

                    detection_event(addr, "RESP",
                                    f"err=0x{err:04x} ({len(resp)}B)",
                                    resp.hex() if verbose else "")

                else:
                    sh, network, unit, dest, src, timer, end_, payload = \
                        parse_extended_frame(frame)

                    # Sequence-number validation
                    sub_summary = f"subhdr=0x{sh:04x} src={src} dlen={len(payload)}"
                    if src <= last_seq:
                        log.warning("[%s] %s:%d seq=%d <= last=%d (possible replay)",
                                    ts, addr[0], addr[1], src, last_seq)
                        sub_summary += f" REPLAY_FLAG"
                    resp_src = src + 1
                    last_seq = src

                    log.info("[%s] %s:%d %s", ts, addr[0], addr[1], sub_summary)
                    detection_event(addr, "REQ", sub_summary, hex_dump)

                    handler = EXT_HANDLERS.get(sh)
                    if handler:
                        resp = handler(sh, network, unit, dest, resp_src,
                                       payload, verbose)
                        err = ERR_SUCCESS
                    else:
                        log.warning("  → Unknown subheader: 0x%04x", sh)
                        resp = build_ext_err(sh, network, unit, dest,
                                             resp_src, ERR_ILLEGAL_CMD)
                        err = ERR_ILLEGAL_CMD

                    detection_event(addr, "RESP",
                                    f"err=0x{err:04x} ({len(resp)}B)",
                                    resp.hex() if verbose else "")

            except ValueError as exc:
                log.warning("[%s] %s:%d Parse error: %s", ts, addr[0], addr[1], exc)
                detection_event(addr, "ERROR", f"Parse error: {exc}", frame.hex())
                break

            conn.sendall(resp)

            # Simulate PLC scan-cycle delay with ±20 % jitter
            if scan_delay > 0:
                jitter = random.uniform(0.8, 1.2)
                time.sleep((scan_delay * jitter) / 1000.0)

    except socket.timeout:
        log.info("Connection %s:%d timed out", addr[0], addr[1])
        detection_event(addr, "CLOSE", "Timeout")
    except ConnectionResetError:
        log.warning("Connection reset by %s", addr[0])
        detection_event(addr, "ERROR", "Connection reset")
    except ConnectionAbortedError:
        log.warning("Connection aborted by %s", addr[0])
        detection_event(addr, "ERROR", "Connection aborted")
    except Exception as exc:
        log.error("Error handling %s: %s", addr[0], exc)
        detection_event(addr, "ERROR", f"Unhandled: {exc}")
    finally:
        conn.close()
        log.info("Connection from %s closed", addr[0])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MELSEC-Q PLC Honeypot — MC protocol 3E-frame emulator",
    )
    parser.add_argument("--port", type=int, default=5007,
                        help="TCP listen port (default: 5007)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--profile",
                        choices=sorted(PROFILES.keys()), default="q03udvcpu",
                        help="PLC device profile (default: q03udvcpu)")
    parser.add_argument("--scan-delay", type=int, default=20,
                        help="Simulated scan delay in ms (default: 20)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging + hex dumps")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug("Verbose mode enabled")

    profile = PROFILES[args.profile]
    init_simulated()

    log.info("MELSEC-Q PLC Honeypot starting")
    log.info("  Profile:   %s  (%s, firmware %s)",
             args.profile, profile["cpu_type"], profile["firmware"])
    log.info("  Listen:    %s:%d", args.host, args.port)
    log.info("  Scan-delay: %d ms", args.scan_delay)
    log.info("  Ready. Press Ctrl+C to stop.")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(5)

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, profile, args.scan_delay, args.verbose),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        server.close()


if __name__ == "__main__":
    main()
