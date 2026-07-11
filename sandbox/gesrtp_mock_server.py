#!/usr/bin/env python3
"""
GE SRTP (Service Request Transport Protocol) Honeypot-Grade PLC Emulator.

Listens on TCP 18245 and emulates GE PACSystems RX3i, 90-70, or 90-30 PLCs,
responding to INIT/INIT_ACK handshake and SRTP service requests with realistic
identification data, configurable timing, per-connection state tracking, and
blue-team detection logging.

Usage:
    python3 gesrtp_mock_server.py                         # Default rx3i on 18245
    python3 gesrtp_mock_server.py --profile ge90_70       # Emulate 90-70 PLC
    python3 gesrtp_mock_server.py --scan-delay 50         # 50ms scan cycle
    python3 gesrtp_mock_server.py --port 18245 --verbose  # Hex dumps enabled

Protocol Overview:
    GE SRTP runs on TCP 18245. Each message is a fixed 56 bytes:

    +--------+--------+--------+------------------+
    | Type   | Index  | Length | Data (50 bytes)  |
    | (2 BE) | (2 BE) | (2 BE) |                  |
    +--------+--------+--------+------------------+

    Packet types:
        0x0000  INIT        (Client -> Server)
        0x0001  INIT_ACK    (Server -> Client)
        0x0002  REQ         (Client -> Server)
        0x0003  REQ_ACK     (Server -> Client)

    Service codes (in REQ data as uint32 BE):
        0   = PLC_SSTAT     (PLC status / identification)
        1   = PLC_LSTAT     (PLC detailed status / memory info)
        67  = RET_CONFIG_INFO (PLC configuration parameters)

    PLC_SSTAT response payload (50 bytes, within REQ_ACK):
        Bytes 0-1:   Status code (uint16 BE)      0x0000 = success
        Bytes 2-3:   PLC state (uint16 BE)        0x0000 = Running
        Bytes 4-23:  PLC model string              null-terminated, 20 bytes
        Bytes 24-33: Firmware version string        null-terminated, 10 bytes
        Bytes 34-49: CPU type string               null-terminated, 16 bytes

    PLC_LSTAT response payload (50 bytes):
        Bytes 0-1:   Status code (uint16 BE)
        Bytes 2-3:   PLC state (uint16 BE)
        Bytes 4-5:   Scan time ms (uint16 BE)
        Bytes 6-7:   Memory used KB (uint16 BE)
        Bytes 8-9:   Memory total KB (uint16 BE)
        Bytes 10-13: Uptime seconds (uint32 BE)
        Bytes 14-15: CPU load pct (uint16 BE)
        Bytes 16-49: Extended info / padding

    RET_CONFIG_INFO response payload (50 bytes):
        Bytes 0-1:   Status code (uint16 BE)
        Bytes 2-17:  CPU module ID (16 bytes, null-terminated)
        Bytes 18-27: Firmware version (10 bytes, null-terminated)
        Bytes 28-29: Max connections (uint16 BE)
        Bytes 30-31: Max services (uint16 BE)
        Bytes 32-33: Protocol version packed (uint16 BE)
        Bytes 34-35: Scan mode flags (uint16 BE)
        Bytes 36-49: Reserved / padding

    Error codes (in status field of REQ_ACK data):
        0x0000 = Success
        0x0001 = InvalidService
        0x0002 = InvalidData
        0x0003 = ResourceUnavailable
        0x0004 = AccessDenied
"""

import argparse
import logging
import socket
import struct
import sys
import threading
import time


# ======================================================================
# SRTP Protocol Constants
# ======================================================================
SRTP_DEFAULT_PORT = 18245
SRTP_PACKET_LEN = 56
SRTP_DATA_LEN = 50
SRTP_HEADER_LEN = 6

PKT_INIT = 0x0000
PKT_INIT_ACK = 0x0001
PKT_REQ = 0x0002
PKT_REQ_ACK = 0x0003

SERVICE_PLC_SSTAT = 0
SERVICE_PLC_LSTAT = 1
SERVICE_RET_CONFIG_INFO = 67

# SRTP error codes (returned in first 2 bytes of REQ_ACK data payload)
ERR_SUCCESS = 0x0000
ERR_INVALID_SERVICE = 0x0001
ERR_INVALID_DATA = 0x0002
ERR_RESOURCE_UNAVAILABLE = 0x0003
ERR_ACCESS_DENIED = 0x0004

DEFAULT_PROFILE = "rx3i"
DEFAULT_SCAN_DELAY_MS = 20

SRTP_ERROR_NAMES = {
    ERR_SUCCESS: "Success",
    ERR_INVALID_SERVICE: "InvalidService",
    ERR_INVALID_DATA: "InvalidData",
    ERR_RESOURCE_UNAVAILABLE: "ResourceUnavailable",
    ERR_ACCESS_DENIED: "AccessDenied",
}


# ======================================================================
# PLC Device Profiles
# ======================================================================

PLC_PROFILES = {
    "rx3i": {
        "model": "GE PACSystems RX3i",
        "firmware": "V9.50",
        "cpu": "IC695CPE302",
        "status": 0x0000,
        "plc_state": 0x0000,
        "scan_time_ms": 20,
        "mem_used_kb": 43008,     # ~42 MB
        "mem_total_kb": 102400,   # 100 MB
        "cpu_load": 23,
    },
    "ge90_70": {
        "model": "GE Fanuc 90-70",
        "firmware": "V7.20",
        "cpu": "IC697CPU772",
        "status": 0x0000,
        "plc_state": 0x0000,
        "scan_time_ms": 35,
        "mem_used_kb": 66560,     # ~65 MB
        "mem_total_kb": 131072,   # 128 MB
        "cpu_load": 45,
    },
    "ge90_30": {
        "model": "GE Fanuc 90-30",
        "firmware": "V6.10",
        "cpu": "IC693CPU374",
        "status": 0x0000,
        "plc_state": 0x0000,
        "scan_time_ms": 50,
        "mem_used_kb": 28672,     # ~28 MB
        "mem_total_kb": 65536,    # 64 MB
        "cpu_load": 30,
    },
}


# ======================================================================
# Connection State Tracker
# ======================================================================

_connection_states: dict[str, dict] = {}
_connection_states_lock = threading.Lock()


def track_connection(addr: tuple) -> dict:
    """Register or retrieve per-connection state.

    Args:
        addr: (ip, port) tuple from accept().

    Returns:
        Connection state dict with keys:
            - client_ip (str)
            - client_port (int)
            - connected_at (float): time.time() of first connection
            - init_state (str): "pending" | "completed"
            - services_requested (list[int]): service codes seen
            - packets_sent (int)
            - packets_received (int)
    """
    key = f"{addr[0]}:{addr[1]}"
    with _connection_states_lock:
        if key not in _connection_states:
            _connection_states[key] = {
                "client_ip": addr[0],
                "client_port": addr[1],
                "connected_at": time.time(),
                "init_state": "pending",
                "services_requested": [],
                "packets_sent": 0,
                "packets_received": 0,
            }
        return _connection_states[key]


def update_connection_state(key: str, **kwargs):
    """Update fields in a connection state dict."""
    with _connection_states_lock:
        if key in _connection_states:
            _connection_states[key].update(kwargs)


def remove_connection_state(addr: tuple):
    """Remove a connection state entry on disconnect."""
    key = f"{addr[0]}:{addr[1]}"
    with _connection_states_lock:
        _connection_states.pop(key, None)


# ======================================================================
# Detection Logger
# ======================================================================

def setup_detection_logger() -> logging.Logger:
    """Configure and return the detection logger.

    Returns:
        Logger instance that writes timestamped detection events
        to stderr with format:
            2026-07-11 12:34:56 [DETECT] 192.168.1.100:49152 -> PLC_SSTAT
    """
    logger = logging.getLogger("gesrtp.detection")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers on re-initialization (e.g. from self_test)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.INFO)
        fmt = logging.Formatter(
            "%(asctime)s [DETECT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)

    return logger


_detection_log = setup_detection_logger()


# ======================================================================
# SRTP Packet Builder
# ======================================================================

def build_srtp_packet(pkt_type: int, pkt_index: int, data: bytes) -> bytes:
    """Build a 56-byte SRTP packet.

    Args:
        pkt_type:  Packet type (e.g. PKT_INIT, PKT_INIT_ACK, etc.)
        pkt_index: Sequence/echo index
        data:      Payload data (0 to 50 bytes); shorter data is
                   zero-padded to 50 bytes.

    Returns:
        56-byte SRTP packet ready for transmission.
    """
    if len(data) > SRTP_DATA_LEN:
        raise ValueError(
            f"SRTP data payload exceeds {SRTP_DATA_LEN} bytes "
            f"(got {len(data)})"
        )
    header = struct.pack(">HHH", pkt_type, pkt_index, len(data))
    payload = data.ljust(SRTP_DATA_LEN, b"\x00")
    return header + payload


def build_init_ack(status: int = 0x0000,
                   proto_major: int = 1,
                   proto_minor: int = 0) -> bytes:
    """Build an INIT_ACK response.

    Data layout (50 bytes):
        Bytes 0-1:   Status code (uint16)          0x0000 = success
        Bytes 2-3:   Protocol major (uint16)       0x0001
        Bytes 4-5:   Protocol minor (uint16)       0x0000
        Bytes 6-49:  Zero padding

    Args:
        status:       Response status (default: 0x0000 success)
        proto_major:  Protocol major version
        proto_minor:  Protocol minor version

    Returns:
        56-byte INIT_ACK packet.
    """
    data = struct.pack(">HHH", status, proto_major, proto_minor)
    return build_srtp_packet(PKT_INIT_ACK, 0x0001, data)


def build_sstat_response(
    plc_model: str = "GE PACSystems RX3i",
    firmware: str = "V9.50",
    cpu_type: str = "IC695CPE302",
    status: int = 0x0000,
    plc_state: int = 0x0000,
) -> bytes:
    """Build a PLC_SSTAT REQ_ACK response with PLC identification info.

    Data layout (50 bytes):
        Bytes 0-1:   Status code (uint16)          0x0000 = success
        Bytes 2-3:   PLC state (uint16)             0x0000 = Running
        Bytes 4-23:  PLC model string               null-terminated, 20 bytes
        Bytes 24-33: Firmware version string         null-terminated, 10 bytes
        Bytes 34-49: CPU type string                null-terminated, 16 bytes

    Wire format (full 56-byte packet offsets for NSE script compatibility):
        Bytes 6-7:   Status code (uint16 BE)
        Bytes 8-9:   PLC state (uint16 BE)
        Bytes 10-29: PLC model string (20 bytes, null-terminated)
        Bytes 30-39: Firmware version (10 bytes, null-terminated)
        Bytes 40-55: CPU type string (16 bytes, null-terminated)

    Args:
        plc_model:  PLC model name string
        firmware:   Firmware version string
        cpu_type:   CPU type / module ID string
        status:     Response status (default: 0x0000 success)
        plc_state:  PLC operating state

    Returns:
        56-byte REQ_ACK packet.
    """
    model_bytes = plc_model.encode("ascii", errors="replace") + b"\x00"
    model_field = model_bytes.ljust(20, b"\x00")[:20]

    fw_bytes = firmware.encode("ascii", errors="replace") + b"\x00"
    fw_field = fw_bytes.ljust(10, b"\x00")[:10]

    cpu_bytes = cpu_type.encode("ascii", errors="replace") + b"\x00"
    cpu_field = cpu_bytes.ljust(16, b"\x00")[:16]

    data = struct.pack(">HH", status, plc_state) + model_field + fw_field + cpu_field

    # Sanity check: data must be exactly 50 bytes
    if len(data) != SRTP_DATA_LEN:
        raise RuntimeError(
            f"PLC_SSTAT data payload is {len(data)} bytes, "
            f"expected {SRTP_DATA_LEN}"
        )

    return build_srtp_packet(PKT_REQ_ACK, 0x0002, data)


def build_lstat_response(
    status: int = 0x0000,
    plc_state: int = 0x0000,
    scan_time_ms: int = 20,
    mem_used_kb: int = 43008,
    mem_total_kb: int = 102400,
    uptime_seconds: int = 3600,
    cpu_load: int = 23,
) -> bytes:
    """Build a PLC_LSTAT REQ_ACK response with detailed status info.

    Data layout (50 bytes):
        Bytes 0-1:   Status code (uint16 BE)
        Bytes 2-3:   PLC state (uint16 BE)
        Bytes 4-5:   Scan time ms (uint16 BE)
        Bytes 6-7:   Memory used KB (uint16 BE)
        Bytes 8-9:   Memory total KB (uint16 BE)
        Bytes 10-13: Uptime seconds (uint32 BE)
        Bytes 14-15: CPU load percent (uint16 BE)
        Bytes 16-49: Padding (zeros)

    Args:
        status:         Response status
        plc_state:      PLC operating state
        scan_time_ms:   Current scan cycle time in ms
        mem_used_kb:    Used memory in KB
        mem_total_kb:   Total memory in KB
        uptime_seconds: PLC uptime in seconds
        cpu_load:       CPU utilization percentage

    Returns:
        56-byte REQ_ACK packet with PLC_LSTAT data.
    """
    data = struct.pack(
        ">HHHHHIH",
        status & 0xFFFF,
        plc_state & 0xFFFF,
        scan_time_ms & 0xFFFF,
        mem_used_kb & 0xFFFF,
        mem_total_kb & 0xFFFF,
        uptime_seconds,
        cpu_load & 0xFFFF,
    )
    data = data.ljust(SRTP_DATA_LEN, b"\x00")[:SRTP_DATA_LEN]
    return build_srtp_packet(PKT_REQ_ACK, 0x0002, data)


def build_config_info_response(
    status: int = 0x0000,
    model: str = "IC695CPE302",
    firmware: str = "V9.50",
    max_connections: int = 32,
    max_services: int = 128,
    protocol_version: str = "1.0",
    scan_mode: str = "normal",
) -> bytes:
    """Build a RET_CONFIG_INFO REQ_ACK response.

    Data layout (50 bytes):
        Bytes 0-1:   Status code (uint16 BE)
        Bytes 2-17:  CPU module ID (16 bytes, null-terminated)
        Bytes 18-27: Firmware version (10 bytes, null-terminated)
        Bytes 28-29: Max connections (uint16 BE)
        Bytes 30-31: Max services (uint16 BE)
        Bytes 32-33: Protocol version packed (uint16 BE)
        Bytes 34-35: Scan mode flags (uint16 BE)
        Bytes 36-49: Reserved / padding

    Args:
        status:           Response status
        model:            CPU module ID string
        firmware:         Firmware version string
        max_connections:  Maximum simultaneous connections
        max_services:     Maximum service codes
        protocol_version: Protocol version string "X.Y"
        scan_mode:        Scan mode identifier

    Returns:
        56-byte REQ_ACK packet with configuration info.
    """
    # Parse protocol version into packed uint16 (major << 8 | minor)
    try:
        proto_parts = protocol_version.split(".")
        proto_packed = (int(proto_parts[0]) << 8) | int(proto_parts[1])
    except (IndexError, ValueError):
        proto_packed = 0x0100

    scan_mode_flags = 0x0001 if scan_mode == "normal" else 0x0000

    # Build fixed-width fields
    model_field = model.encode("ascii", errors="replace")[:15].ljust(16, b"\x00")
    fw_field = firmware.encode("ascii", errors="replace")[:9].ljust(10, b"\x00")

    data = struct.pack(">H", status)
    data += model_field
    data += fw_field
    data += struct.pack(
        ">HHHH",
        max_connections & 0xFFFF,
        max_services & 0xFFFF,
        proto_packed,
        scan_mode_flags,
    )
    data = data.ljust(SRTP_DATA_LEN, b"\x00")[:SRTP_DATA_LEN]
    return build_srtp_packet(PKT_REQ_ACK, 0x0002, data)


def build_error_response(error_code: int, pkt_index: int = 0x0002) -> bytes:
    """Build a REQ_ACK response carrying an SRTP error code.

    Args:
        error_code: One of the ERR_* constants.
        pkt_index:  Index to echo back (default: 0x0002).

    Returns:
        56-byte REQ_ACK packet with error code at data offset 0-1.
    """
    data = struct.pack(">H", error_code)
    data = data.ljust(SRTP_DATA_LEN, b"\x00")[:SRTP_DATA_LEN]
    return build_srtp_packet(PKT_REQ_ACK, pkt_index, data)


# ======================================================================
# SRTP Packet Parser
# ======================================================================

def parse_srtp_packet(data: bytes) -> tuple[int, int, int, bytes]:
    """Parse a raw SRTP packet into its header fields.

    Args:
        data:  Raw bytes received (at least 6 bytes needed).

    Returns:
        Tuple of (pkt_type, pkt_index, data_length, payload).

    Raises:
        ValueError: If the packet is too short to contain an SRTP header.
    """
    if len(data) < SRTP_HEADER_LEN:
        raise ValueError(
            f"Packet too short: {len(data)} bytes, "
            f"need at least {SRTP_HEADER_LEN}"
        )

    pkt_type, pkt_index, data_length = struct.unpack(
        ">HHH", data[:SRTP_HEADER_LEN]
    )
    payload = data[SRTP_HEADER_LEN:]

    return pkt_type, pkt_index, data_length, payload


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a socket, looping until complete.

    Handles partial TCP reads gracefully. Returns an empty bytes object
    if the connection is closed before n bytes are received.

    Args:
        sock: Connected socket object.
        n:    Number of bytes to receive.

    Returns:
        Exactly n bytes of data, or fewer if the connection was closed.
    """
    chunks = []
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except (ConnectionResetError, ConnectionAbortedError):
            return b""
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ======================================================================
# Hex Dump Utility
# ======================================================================

def hex_dump(data: bytes, label: str = "", max_bytes: int = 256) -> str:
    """Return a formatted hex dump of binary data.

    Format:
        <label> (N bytes)
        0000  48 65 6C 6C 6F 57 6F 72  6C 64 00 00 00 00 00 00  HelloWor ld......

    Args:
        data:     Binary data to dump
        label:    Optional label prefix
        max_bytes: Truncate dump to this many bytes (default: 256)

    Returns:
        Multi-line hex dump string.
    """
    if not data:
        return f"{label} (empty)"

    show = data[:max_bytes]
    truncated = len(data) > max_bytes
    lines = [f"{label} ({len(data)} bytes)"
             + (" (truncated)" if truncated else "")]

    for i in range(0, len(show), 16):
        chunk = show[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
        if len(chunk) > 8:
            hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        else:
            hex_part += "  " if len(chunk) > 8 else ""
        hex_part = hex_part.ljust(49)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "."
                             for b in chunk)
        lines.append(f"  {i:04x}  {hex_part} {ascii_part}")

    return "\n".join(lines)


# ======================================================================
# PLC State / Service Name Maps
# ======================================================================

PLC_STATE_NAMES = {
    0x0000: "Running",
    0x0001: "Stopped",
    0x0002: "Faulted",
    0x0003: "Halted",
    0x0004: "Debug",
}

SERVICE_NAMES = {
    SERVICE_PLC_SSTAT: "PLC_SSTAT",
    SERVICE_PLC_LSTAT: "PLC_LSTAT",
    SERVICE_RET_CONFIG_INFO: "RET_CONFIG_INFO",
}


# ======================================================================
# Client Handler
# ======================================================================

def handle_client(conn, addr, profile: str, scan_delay_ms: int,
                  verbose: bool = False):
    """Handle a single SRTP client connection.

    Implements the protocol state machine:
        INIT -> INIT_ACK -> REQ -> REQ_ACK -> (optional more REQs) -> CLOSE

    Args:
        conn:          Connected socket.
        addr:          (ip, port) tuple from accept().
        profile:       PLC profile key from PLC_PROFILES.
        scan_delay_ms: Simulated PLC scan delay in ms.
        verbose:       Enable hex dump logging.
    """
    addr_str = f"{addr[0]}:{addr[1]}"
    prof = PLC_PROFILES.get(profile, PLC_PROFILES[DEFAULT_PROFILE])
    state = track_connection(addr)

    print(f"\n[+] Connection from {addr_str}")
    _detection_log.info(
        "%s -> CONNECT (profile=%s)", addr_str, profile
    )

    try:
        # ---- State: Awaiting INIT -----------------------------------
        data = recv_exact(conn, SRTP_PACKET_LEN)
        if not data or len(data) < SRTP_PACKET_LEN:
            print(f"  [!] {addr_str}: Connection closed or partial read "
                  f"during INIT (got {len(data)} bytes)")
            return

        try:
            pkt_type, pkt_index, data_length, payload = parse_srtp_packet(data)
        except ValueError as e:
            print(f"  [!] {addr_str}: Malformed INIT: {e}")
            return

        if pkt_type != PKT_INIT:
            print(f"  [!] {addr_str}: Expected INIT (0x0000), "
                  f"got 0x{pkt_type:04x}")
            return

        # Validate: INIT should have minimal or zero payload
        if data_length > 0:
            print(f"  [WARN] {addr_str}: INIT has non-zero data_length "
                  f"({data_length})")

        update_connection_state(addr_str, init_state="completed")
        state["packets_received"] += 1

        if verbose:
            print(f"\n  [{addr_str}] <- INIT "
                  f"(index=0x{pkt_index:04x}, len={data_length})")
            print(hex_dump(data, label="  [Hex RX]"))
        else:
            print(f"  [{addr_str}] <- INIT "
                  f"(index=0x{pkt_index:04x}, len={data_length})")

        # Simulate PLC scan cycle delay before responding
        if scan_delay_ms > 0:
            time.sleep(scan_delay_ms / 1000.0)

        # ---- Send INIT_ACK ------------------------------------------
        init_ack = build_init_ack()
        conn.sendall(init_ack)
        state["packets_sent"] += 1

        if verbose:
            print(f"  [{addr_str}] -> INIT_ACK (56 bytes)")
            print(hex_dump(init_ack, label="  [Hex TX]"))
        else:
            print(f"  [{addr_str}] -> INIT_ACK (56 bytes)")

        # ---- State: Awaiting REQ(s) ---------------------------------
        while True:
            data = recv_exact(conn, SRTP_PACKET_LEN)
            if not data or len(data) < SRTP_PACKET_LEN:
                print(f"  [{addr_str}] Connection closed or partial read "
                      f"(got {len(data)} bytes)")
                break

            try:
                pkt_type, pkt_index, data_length, payload = parse_srtp_packet(data)
            except ValueError as e:
                print(f"  [!] {addr_str}: Malformed packet: {e}")
                break

            state["packets_received"] += 1

            if pkt_type != PKT_REQ:
                print(f"  [!] {addr_str}: Expected REQ (0x0002), "
                      f"got 0x{pkt_type:04x}")
                if verbose:
                    print(hex_dump(data, label="  [Hex RX]"))
                break

            # Validate REQ data length (must have at least 4 bytes for service code)
            if data_length < 4:
                print(f"  [!] {addr_str}: REQ data_length too small "
                      f"({data_length}, need >= 4)")
                err_pkt = build_error_response(ERR_INVALID_DATA, pkt_index)
                conn.sendall(err_pkt)
                state["packets_sent"] += 1
                break

            # Extract service code (first 4 bytes, uint32 BE)
            service_code = struct.unpack(">I", payload[:4])[0]
            service_name = SERVICE_NAMES.get(
                service_code, f"UNKNOWN({service_code})"
            )

            # Track service in connection state
            state["services_requested"].append(service_code)

            # Detection log: every service request with client and service info
            _detection_log.info(
                "%s -> %s (code=%d)",
                addr_str, service_name, service_code,
            )

            if verbose:
                print(f"\n  [{addr_str}] <- REQ: "
                      f"service={service_name} (code={service_code})")
                print(hex_dump(data, label="  [Hex RX]"))
            else:
                print(f"  [{addr_str}] <- REQ: "
                      f"service={service_name} (code={service_code})")

            # Simulate PLC scan cycle delay before responding
            if scan_delay_ms > 0:
                time.sleep(scan_delay_ms / 1000.0)

            # Dispatch by service code
            if service_code == SERVICE_PLC_SSTAT:
                response = build_sstat_response(
                    plc_model=prof["model"],
                    firmware=prof["firmware"],
                    cpu_type=prof["cpu"],
                    status=prof["status"],
                    plc_state=prof["plc_state"],
                )
                print(f"  [{addr_str}] -> REQ_ACK: PLC_SSTAT "
                      f"(model={prof['model']}, fw={prof['firmware']})")
                if verbose:
                    print(hex_dump(response, label="  [Hex TX]"))
                conn.sendall(response)
                state["packets_sent"] += 1

            elif service_code == SERVICE_PLC_LSTAT:
                uptime_secs = int(time.time() - state["connected_at"])
                response = build_lstat_response(
                    status=prof["status"],
                    plc_state=prof["plc_state"],
                    scan_time_ms=prof["scan_time_ms"],
                    mem_used_kb=prof["mem_used_kb"],
                    mem_total_kb=prof["mem_total_kb"],
                    uptime_seconds=uptime_secs,
                    cpu_load=prof["cpu_load"],
                )
                print(f"  [{addr_str}] -> REQ_ACK: PLC_LSTAT "
                      f"(scan={prof['scan_time_ms']}ms, "
                      f"mem={prof['mem_used_kb'] // 1024}"
                      f"/{prof['mem_total_kb'] // 1024}MB)")
                if verbose:
                    print(hex_dump(response, label="  [Hex TX]"))
                conn.sendall(response)
                state["packets_sent"] += 1

            elif service_code == SERVICE_RET_CONFIG_INFO:
                # Determine max connections per profile
                if profile == "rx3i":
                    max_conn = 32
                    max_serv = 128
                elif profile == "ge90_70":
                    max_conn = 16
                    max_serv = 64
                else:
                    max_conn = 8
                    max_serv = 64

                response = build_config_info_response(
                    status=prof["status"],
                    model=prof["cpu"],
                    firmware=prof["firmware"],
                    max_connections=max_conn,
                    max_services=max_serv,
                    protocol_version="1.0",
                    scan_mode="normal",
                )
                print(f"  [{addr_str}] -> REQ_ACK: RET_CONFIG_INFO "
                      f"(cpu={prof['cpu']})")
                if verbose:
                    print(hex_dump(response, label="  [Hex TX]"))
                conn.sendall(response)
                state["packets_sent"] += 1

            else:
                # Unknown service - respond with InvalidService error
                response = build_error_response(ERR_INVALID_SERVICE, pkt_index)
                print(f"  [{addr_str}] -> REQ_ACK: ERROR "
                      f"InvalidService (code={service_code})")
                if verbose:
                    print(hex_dump(response, label="  [Hex TX]"))
                conn.sendall(response)
                state["packets_sent"] += 1
                # Do NOT break - some scanners probe multiple services

    except socket.timeout:
        print(f"  [{addr_str}] Timeout")
    except ConnectionResetError:
        print(f"  [{addr_str}] Connection reset")
    except ConnectionAbortedError:
        print(f"  [{addr_str}] Connection aborted")
    except Exception as e:
        print(f"  [{addr_str}] Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()
        remove_connection_state(addr)
        print(f"  [-] {addr_str} disconnected")


# ======================================================================
# Server
# ======================================================================

def run_server(port: int = SRTP_DEFAULT_PORT, profile: str = DEFAULT_PROFILE,
               scan_delay_ms: int = DEFAULT_SCAN_DELAY_MS,
               verbose: bool = False):
    """Run the GE SRTP mock server until Ctrl+C is pressed.

    Args:
        port:         TCP port to listen on (default: 18245)
        profile:      PLC profile key from PLC_PROFILES
        scan_delay_ms: Simulated PLC scan delay in ms
        verbose:      Enable hex dump logging
    """
    prof = PLC_PROFILES.get(profile, PLC_PROFILES[DEFAULT_PROFILE])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(1.0)
    except OSError as e:
        print(f"[FATAL] Cannot bind to 127.0.0.1:{port}: {e}")
        print("       Try a different port with --port, or check if")
        print("       another process is already using this port.")
        sys.exit(1)

    print(f"{'='*60}")
    print(f"  GE SRTP Honeypot-Grade PLC Emulator")
    print(f"  Listening on:  127.0.0.1:{port}")
    print(f"  PLC Profile:   {profile}")
    print(f"  PLC Model:     {prof['model']}")
    print(f"  Firmware:      {prof['firmware']}")
    print(f"  CPU Type:      {prof['cpu']}")
    print(f"  Scan Delay:    {scan_delay_ms}ms")
    print(f"  Verbose mode:  {'ON' if verbose else 'OFF'}")
    print(f"  Detection log: stderr (ISO 8601 timestamps)")
    print(f"{'='*60}")
    print()
    print("  Press Ctrl+C to stop.")
    print()

    client_id = 0

    try:
        while True:
            try:
                conn, addr = sock.accept()
                client_id += 1
                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, profile, scan_delay_ms, verbose),
                    daemon=True,
                    name=f"srtp-client-{client_id}",
                )
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[!] Shutting down (Ctrl+C detected)")
    finally:
        sock.close()
        print(f"[OK] Server stopped. Active connections: "
              f"{threading.active_count() - 1}")


# ======================================================================
# Self-Test
# ======================================================================

def self_test():
    """Run a quick self-test to verify packet construction and parsing."""
    print("[SELF-TEST] Verifying SRTP packet builder and parser...\n")

    # Test 1: Build INIT_ACK
    init_ack = build_init_ack()
    assert len(init_ack) == SRTP_PACKET_LEN, (
        f"INIT_ACK length: expected {SRTP_PACKET_LEN}, "
        f"got {len(init_ack)}"
    )
    pkt_type, pkt_idx, data_len, payload = parse_srtp_packet(init_ack)
    assert pkt_type == PKT_INIT_ACK, (
        f"INIT_ACK type: expected 0x{PKT_INIT_ACK:04x}, "
        f"got 0x{pkt_type:04x}"
    )
    assert pkt_idx == 0x0001, (
        f"INIT_ACK index: expected 0x0001, got 0x{pkt_idx:04x}"
    )
    print(f"  [PASS] INIT_ACK: type=0x{pkt_type:04x} "
          f"index=0x{pkt_idx:04x} data_len={data_len} "
          f"total={len(init_ack)}B")

    # Test 2: Build PLC_SSTAT response with default profile
    sstat = build_sstat_response()
    assert len(sstat) == SRTP_PACKET_LEN, (
        f"SSTAT length: expected {SRTP_PACKET_LEN}, "
        f"got {len(sstat)}"
    )
    pkt_type, pkt_idx, data_len, payload = parse_srtp_packet(sstat)
    assert pkt_type == PKT_REQ_ACK, (
        f"SSTAT type: expected 0x{PKT_REQ_ACK:04x}, "
        f"got 0x{pkt_type:04x}"
    )

    # Parse string fields from known payload offsets
    model = payload[4:24].rstrip(b"\x00").decode("ascii")
    fw = payload[24:34].rstrip(b"\x00").decode("ascii")
    cpu = payload[34:50].rstrip(b"\x00").decode("ascii")

    print(f"  [PASS] PLC_SSTAT: model='{model}' fw='{fw}' cpu='{cpu}'")
    assert model == "GE PACSystems RX3i", f"Model mismatch: '{model}'"
    assert fw == "V9.50", f"FW mismatch: '{fw}'"
    assert cpu == "IC695CPE302", f"CPU mismatch: '{cpu}'"

    # Test 3: Build PLC_SSTAT with alternate profile (90-70)
    sstat90 = build_sstat_response(
        plc_model="GE Fanuc 90-70",
        firmware="V7.20",
        cpu_type="IC697CPU772",
        plc_state=0x0001,
    )
    _, _, _, payload90 = parse_srtp_packet(sstat90)
    model90 = payload90[4:24].rstrip(b"\x00").decode("ascii")
    fw90 = payload90[24:34].rstrip(b"\x00").decode("ascii")
    cpu90 = payload90[34:50].rstrip(b"\x00").decode("ascii")
    assert model90 == "GE Fanuc 90-70", f"90-70 model: '{model90}'"
    assert cpu90 == "IC697CPU772", f"90-70 cpu: '{cpu90}'"
    print(f"  [PASS] PLC_SSTAT (90-70): model='{model90}' "
          f"fw='{fw90}' cpu='{cpu90}'")

    # Test 4: Build PLC_LSTAT response
    lstat = build_lstat_response(
        scan_time_ms=35, mem_used_kb=66560, mem_total_kb=131072,
        uptime_seconds=7200, cpu_load=45,
    )
    assert len(lstat) == SRTP_PACKET_LEN
    _, _, _, lpayload = parse_srtp_packet(lstat)
    l_scan_time = struct.unpack(">H", lpayload[4:6])[0]
    l_mem_used = struct.unpack(">H", lpayload[6:8])[0]
    l_uptime = struct.unpack(">I", lpayload[10:14])[0]
    assert l_scan_time == 35, f"LSTAT scan_time: expected 35, got {l_scan_time}"
    assert l_uptime == 7200, f"LSTAT uptime: expected 7200, got {l_uptime}"
    print(f"  [PASS] PLC_LSTAT: scan={l_scan_time}ms "
          f"mem={l_mem_used}KB uptime={l_uptime}s")

    # Test 5: Build RET_CONFIG_INFO response
    cfg = build_config_info_response(model="IC695CPE302", firmware="V9.50")
    assert len(cfg) == SRTP_PACKET_LEN
    _, _, _, cpayload = parse_srtp_packet(cfg)
    c_model = cpayload[2:18].rstrip(b"\x00").decode("ascii")
    assert c_model == "IC695CPE302", f"CFG model: '{c_model}'"
    print(f"  [PASS] RET_CONFIG_INFO: cpu='{c_model}'")

    # Test 6: Build error response with known error code
    err_pkt = build_error_response(ERR_INVALID_SERVICE)
    _, _, _, epayload = parse_srtp_packet(err_pkt)
    err_code = struct.unpack(">H", epayload[:2])[0]
    assert err_code == ERR_INVALID_SERVICE, (
        f"Error code: expected 0x{ERR_INVALID_SERVICE:04x}, "
        f"got 0x{err_code:04x}"
    )
    print(f"  [PASS] ERROR: code=0x{err_code:04x} "
          f"({SRTP_ERROR_NAMES.get(err_code, '?')})")

    # Test 7: Build error response with AccessDenied
    err_deny = build_error_response(ERR_ACCESS_DENIED)
    _, _, _, edata = parse_srtp_packet(err_deny)
    assert struct.unpack(">H", edata[:2])[0] == ERR_ACCESS_DENIED
    print(f"  [PASS] ERROR: AccessDenied (0x{ERR_ACCESS_DENIED:04x})")

    # Test 8: Build INIT
    init = build_srtp_packet(PKT_INIT, 0x0001, b"")
    assert len(init) == SRTP_PACKET_LEN
    pkt_type, pkt_idx, data_len, payload = parse_srtp_packet(init)
    assert pkt_type == PKT_INIT
    assert data_len == 0
    assert all(b == 0 for b in payload)
    print(f"  [PASS] INIT: type=0x{pkt_type:04x} "
          f"index=0x{pkt_idx:04x} data_len={data_len}")

    # Test 9: Hex dump sanity
    dump = hex_dump(init, label="INIT")
    assert "INIT" in dump
    assert "0000" in dump
    print(f"  [PASS] hex_dump: output has {len(dump)} chars")

    # Test 10: recv_exact docstring present
    assert recv_exact.__doc__ is not None, "recv_exact missing docstring"
    print(f"  [PASS] recv_exact docstring present")

    # Test 11: Edge case - payload too large
    try:
        build_srtp_packet(PKT_REQ, 0x0002, b"A" * 51)
        print("  [FAIL] build_srtp_packet should reject >50 byte payload")
    except ValueError:
        print("  [PASS] build_srtp_packet rejects oversized payload")

    # Test 12: Profile consistency
    for pname, pdata in PLC_PROFILES.items():
        assert len(pdata["model"]) > 0, f"Profile {pname}: empty model"
        assert len(pdata["firmware"]) > 0, f"Profile {pname}: empty firmware"
        assert len(pdata["cpu"]) > 0, f"Profile {pname}: empty cpu"
        print(f"  [PASS] Profile '{pname}': {pdata['model']} "
              f"fw={pdata['firmware']} cpu={pdata['cpu']}")

    # Test 13: Connection state tracking
    state = track_connection(("192.0.2.1", 49152))
    assert state["client_ip"] == "192.0.2.1"
    assert state["init_state"] == "pending"
    update_connection_state(
        f"{state['client_ip']}:{state['client_port']}",
        init_state="completed",
    )
    assert state["init_state"] == "completed"
    remove_connection_state(("192.0.2.1", 49152))
    print(f"  [PASS] Connection state tracking: create/update/remove")

    print(f"\n[SELF-TEST] All tests passed.")


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="GE SRTP (Service Request Transport Protocol) "
                    "Honeypot-Grade PLC Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 gesrtp_mock_server.py
    Start on default port 18245 with RX3i profile and standard logging.

  python3 gesrtp_mock_server.py --profile ge90_70
    Emulate a GE Fanuc 90-70 PLC (IC697CPU772, V7.20).

  python3 gesrtp_mock_server.py --profile ge90_30 --scan-delay 50
    Emulate a 90-30 PLC with 50ms simulated scan cycle.

  python3 gesrtp_mock_server.py --port 18245 --verbose
    Start with hex dump logging enabled.

  python3 gesrtp_mock_server.py --container
    Run in container mode (bind to 0.0.0.0).

  python3 gesrtp_mock_server.py --self-test
    Run built-in packet tests and exit.
        """,
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=SRTP_DEFAULT_PORT,
        help=f"TCP port to listen on (default: {SRTP_DEFAULT_PORT})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose hex dump logging",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=DEFAULT_PROFILE,
        choices=sorted(PLC_PROFILES.keys()),
        help=f"PLC device profile (default: {DEFAULT_PROFILE})",
    )
    parser.add_argument(
        "--scan-delay",
        type=int,
        default=DEFAULT_SCAN_DELAY_MS,
        metavar="MS",
        help=f"Simulated PLC scan cycle delay in ms "
             f"(default: {DEFAULT_SCAN_DELAY_MS}, range: 0-100)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in self-test and exit",
    )

    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    # Clamp scan delay to reasonable bounds (0 = disable timing simulation)
    scan_delay = max(0, min(100, args.scan_delay))

    run_server(
        port=args.port,
        profile=args.profile,
        scan_delay_ms=scan_delay,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
