#!/usr/bin/env python3
"""
GE SRTP (Service Request Transport Protocol) Mock Server.

Listens on TCP 18245 and emulates a GE PACSystems RX3i PLC, responding to
INIT/INIT_ACK handshake and PLC_SSTAT service requests with realistic
identification data.

Usage:
    python3 gesrtp_mock_server.py             # Run on default port 18245
    python3 gesrtp_mock_server.py --port 18245 # Explicit port
    python3 gesrtp_mock_server.py --verbose    # Include hex dumps in logs

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
        1   = PLC_LSTAT     (PLC detailed status)
        67  = RET_CONFIG_INFO
"""

import argparse
import socket
import struct
import sys
import time
from threading import Thread


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

    Args:
        plc_model:  PLC model name string
        firmware:   Firmware version string
        cpu_type:   CPU type / module ID string
        status:     Response status (default: 0x0000 success)
        plc_state:  PLC operating state

    Returns:
        56-byte REQ_ACK packet.
    """
    # Pack identification fields as fixed-width null-terminated strings
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

def handle_client(conn, addr, verbose: bool = False):
    """Handle a single SRTP client connection.

    Implements the protocol state machine:
        INIT -> INIT_ACK -> REQ -> REQ_ACK -> (optional more REQs) -> CLOSE
    """
    addr_str = f"{addr[0]}:{addr[1]}"
    print(f"\n[+] Connection from {addr_str}")

    try:
        # ---- State: Awaiting INIT -----------------------------------
        data = conn.recv(SRTP_PACKET_LEN)
        if not data:
            print(f"  [!] {addr_str}: Connection closed before INIT")
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

        if verbose:
            print(f"\n  [{addr_str}] <- INIT "
                  f"(index=0x{pkt_index:04x}, len={data_length})")
            print(hex_dump(data, label="  [Hex RX]"))
        else:
            print(f"  [{addr_str}] <- INIT "
                  f"(index=0x{pkt_index:04x}, len={data_length})")

        # ---- Send INIT_ACK ------------------------------------------
        init_ack = build_init_ack()
        conn.sendall(init_ack)

        if verbose:
            print(f"  [{addr_str}] -> INIT_ACK (56 bytes)")
            print(hex_dump(init_ack, label="  [Hex TX]"))
        else:
            print(f"  [{addr_str}] -> INIT_ACK (56 bytes)")

        # ---- State: Awaiting REQ(s) ---------------------------------
        while True:
            data = conn.recv(SRTP_PACKET_LEN)
            if not data:
                print(f"  [{addr_str}] Connection closed")
                break

            try:
                pkt_type, pkt_index, data_length, payload = parse_srtp_packet(data)
            except ValueError as e:
                print(f"  [!] {addr_str}: Malformed packet: {e}")
                break

            if pkt_type == PKT_REQ:
                # Extract service code (first 4 bytes, uint32 BE)
                if len(payload) >= 4:
                    service_code = struct.unpack(">I", payload[:4])[0]
                else:
                    service_code = 0

                service_name = SERVICE_NAMES.get(
                    service_code, f"UNKNOWN({service_code})"
                )

                if verbose:
                    print(f"\n  [{addr_str}] <- REQ: "
                          f"service={service_name} (code={service_code})")
                    print(hex_dump(data, label="  [Hex RX]"))
                else:
                    print(f"  [{addr_str}] <- REQ: "
                          f"service={service_name} (code={service_code})")

                # Dispatch by service code
                if service_code == SERVICE_PLC_SSTAT:
                    response = build_sstat_response()
                    print(f"  [{addr_str}] -> REQ_ACK: PLC_SSTAT response")
                    if verbose:
                        print(hex_dump(response, label="  [Hex TX]"))
                    conn.sendall(response)

                elif service_code == SERVICE_PLC_LSTAT:
                    # Extended status - return minimal placeholder
                    lstat_data = struct.pack(">HH", 0x0000, 0x0000)
                    lstat_data += b"LSTAT\0".ljust(46, b"\x00")[:46]
                    response = build_srtp_packet(
                        PKT_REQ_ACK, pkt_index, lstat_data
                    )
                    print(f"  [{addr_str}] -> REQ_ACK: PLC_LSTAT response")
                    conn.sendall(response)

                elif service_code == SERVICE_RET_CONFIG_INFO:
                    cfg_data = (
                        b"CFG\0"
                        + b"IC695CPE302\0"
                        + struct.pack(">I", 0x00040000)
                    ).ljust(SRTP_DATA_LEN, b"\x00")[:SRTP_DATA_LEN]
                    response = build_srtp_packet(
                        PKT_REQ_ACK, pkt_index, cfg_data
                    )
                    print(f"  [{addr_str}] -> REQ_ACK: "
                          f"RET_CONFIG_INFO response")
                    conn.sendall(response)

                else:
                    # Unknown service - respond with error status
                    err_data = struct.pack(">H", 0x0001)
                    err_data = err_data.ljust(SRTP_DATA_LEN, b"\x00")[
                        :SRTP_DATA_LEN
                    ]
                    response = build_srtp_packet(
                        PKT_REQ_ACK, pkt_index, err_data
                    )
                    print(f"  [{addr_str}] -> REQ_ACK: ERROR "
                          f"(unknown service {service_code})")
                    conn.sendall(response)

            else:
                print(f"  [!] {addr_str}: Unexpected packet type "
                      f"0x{pkt_type:04x}")
                if verbose:
                    print(hex_dump(data, label="  [Hex RX]"))
                break

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
        print(f"  [-] {addr_str} disconnected")


# ======================================================================
# Server
# ======================================================================

def run_server(port: int = SRTP_DEFAULT_PORT, verbose: bool = False):
    """Run the GE SRTP mock server until Ctrl+C is pressed.

    Args:
        port:    TCP port to listen on (default: 18245)
        verbose: Enable hex dump logging
    """
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
    print(f"  GE SRTP Mock Server")
    print(f"  Listening on:  127.0.0.1:{port}")
    print(f"  PLC Model:     GE PACSystems RX3i")
    print(f"  Firmware:      V9.50")
    print(f"  CPU Type:      IC695CPE302")
    print(f"  Verbose mode:  {'ON' if verbose else 'OFF'}")
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
                t = Thread(
                    target=handle_client,
                    args=(conn, addr, verbose),
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
        print("[OK] Server stopped.")


# ======================================================================
# Self-Test
# ======================================================================

def self_test():
    """Run a quick self-test to verify packet construction and parsing."""
    print("[SELF-TEST] Verifying SRTP packet builder and parser...")

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

    # Test 2: Build PLC_SSTAT response
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

    # Parse string fields from known offsets
    model = payload[4:24].rstrip(b"\x00").decode("ascii")
    fw = payload[24:34].rstrip(b"\x00").decode("ascii")
    cpu = payload[34:50].rstrip(b"\x00").decode("ascii")

    print(f"  [PASS] PLC_SSTAT: model='{model}' "
          f"fw='{fw}' cpu='{cpu}'")
    assert model == "GE PACSystems RX3i", f"Model mismatch: '{model}'"
    assert fw == "V9.50", f"FW mismatch: '{fw}'"
    assert cpu == "IC695CPE302", f"CPU mismatch: '{cpu}'"

    # Test 3: Build INIT
    init = build_srtp_packet(PKT_INIT, 0x0001, b"")
    assert len(init) == SRTP_PACKET_LEN
    pkt_type, pkt_idx, data_len, payload = parse_srtp_packet(init)
    assert pkt_type == PKT_INIT
    assert data_len == 0
    assert all(b == 0 for b in payload)
    print(f"  [PASS] INIT: type=0x{pkt_type:04x} "
          f"index=0x{pkt_idx:04x} data_len={data_len} "
          f"all_zeros={all(b == 0 for b in payload)}")

    # Test 4: Hex dump sanity
    dump = hex_dump(init, label="INIT")
    assert "INIT" in dump
    assert "0000" in dump
    print(f"  [PASS] hex_dump: output has {len(dump)} chars")

    # Test 5: Edge case - payload too large
    try:
        build_srtp_packet(PKT_REQ, 0x0002, b"A" * 51)
        print("  [FAIL] build_srtp_packet should reject >50 byte payload")
    except ValueError:
        print("  [PASS] build_srtp_packet rejects oversized payload")

    print("\n[SELF-TEST] All tests passed.")


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="GE SRTP (Service Request Transport Protocol) Mock Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 gesrtp_mock_server.py
    Start on default port 18245 with standard logging.

  python3 gesrtp_mock_server.py --port 18245 --verbose
    Start with hex dump logging.

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
        "--self-test",
        action="store_true",
        help="Run built-in self-test and exit",
    )

    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    run_server(port=args.port, verbose=args.verbose)


if __name__ == "__main__":
    main()
