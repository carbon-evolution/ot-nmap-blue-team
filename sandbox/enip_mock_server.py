#!/usr/bin/env python3
"""
EtherNet/IP (CIP) ListIdentity Honeypot-Grade Emulator.

Listens on TCP 44818 and emulates an EtherNet/IP device, responding to the
CIP encapsulation ListIdentity command (0x0063) with a realistic Identity
CPF item. Supports multiple device profiles, per-connection handling,
blue-team detection logging, scan-cycle jitter, and clean SIGTERM shutdown.

Usage:
    python3 enip_mock_server.py                            # controllogix @ 44818
    python3 enip_mock_server.py --profile omron_nx         # OMRON NX102
    python3 enip_mock_server.py --profile micro850 --port 4444
    python3 enip_mock_server.py --self-test                # packet round-trip

Protocol Overview (EtherNet/IP encapsulation, all little-endian):
    A ListIdentity request is a 24-byte encapsulation header:
        command        (uint16)  0x0063
        length         (uint16)  0
        session handle (uint32)  0
        status         (uint32)  0
        sender context (8 bytes) any
        options        (uint32)  0

    The ListIdentity response repeats the header (nonzero length), then:
        item count     (uint16)  1
      one CPF item:
        item type      (uint16)  0x000C  (Identity)
        item length    (uint16)  len(identity body)
      Identity body:
        protocol_version (uint16)
        socket_address   (16 bytes: int16 sin_family, uint16 BE port,
                          uint32 BE addr, 8 bytes zero)
        vendor_id        (uint16)
        device_type      (uint16)
        product_code     (uint16)
        revision_major   (uint8)
        revision_minor   (uint8)
        status           (uint16)
        serial_number    (uint32)
        product_name_len (uint8)
        product_name     (ASCII, that many bytes)
        state            (uint8)
"""

import argparse
import logging
import signal
import socket
import struct
import sys
import threading
import time

# ======================================================================
# EtherNet/IP Encapsulation Constants
# ======================================================================
ENIP_DEFAULT_PORT = 44818
CMD_LIST_IDENTITY = 0x0063
CPF_ITEM_IDENTITY = 0x000C
ENIP_HEADER_LEN = 24

DEFAULT_PROFILE = "controllogix"
DEFAULT_SCAN_DELAY_MS = 15

# ======================================================================
# Device Profiles
# ======================================================================
# Each profile varies vendor / product code / serial / product name so a
# scanner can distinguish them. Fields map 1:1 onto the Identity body.
PROFILES = {
    "controllogix": {
        "vendor_id": 1,
        "device_type": 14,
        "product_code": 54,
        "revision": (20, 11),
        "serial": 0x00C0FFEE,
        "product_name": "1756-L61/B LOGIX5561",
        "state": 3,
    },
    "micro850": {
        "vendor_id": 1,
        "device_type": 14,
        "product_code": 140,
        "revision": (12, 11),
        "serial": 0x00D1E5EE,
        "product_name": "2080-LC50-24QWB",
        "state": 3,
    },
    "omron_nx": {
        "vendor_id": 47,
        "device_type": 14,
        "product_code": 9000,
        "revision": (1, 13),
        "serial": 0x00AB1201,
        "product_name": "NX102-9000",
        "state": 3,
    },
}

PROTOCOL_VERSION = 1


# ======================================================================
# Detection Logger
# ======================================================================
def setup_detection_logger() -> logging.Logger:
    """Configure and return the detection logger (writes to stderr)."""
    logger = logging.getLogger("enip.detection")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [DETECT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(handler)
    return logger


_detection_log = setup_detection_logger()


# ======================================================================
# Packet Builder
# ======================================================================
def build_identity_body(prof: dict) -> bytes:
    """Build the Identity CPF item body from a profile dict.

    Returns the raw Identity body (protocol_version .. state), all
    little-endian except the socket-address port/addr which are BE.
    """
    name = prof["product_name"].encode("ascii", errors="replace")
    rev_major, rev_minor = prof["revision"]

    body = struct.pack("<H", PROTOCOL_VERSION)
    # socket_address: int16 sin_family, uint16 BE port, uint32 BE addr, 8 zero
    body += struct.pack(">hHI", 2, ENIP_DEFAULT_PORT, 0x7F000001)
    body += b"\x00" * 8
    body += struct.pack("<H", prof["vendor_id"] & 0xFFFF)
    body += struct.pack("<H", prof["device_type"] & 0xFFFF)
    body += struct.pack("<H", prof["product_code"] & 0xFFFF)
    body += struct.pack("BB", rev_major & 0xFF, rev_minor & 0xFF)
    body += struct.pack("<H", 0x0000)  # device status word
    body += struct.pack("<I", prof["serial"] & 0xFFFFFFFF)
    body += struct.pack("B", len(name) & 0xFF)
    body += name
    body += struct.pack("B", prof["state"] & 0xFF)
    return body


def build_list_identity_response(prof: dict,
                                 sender_context: bytes = b"\x00" * 8) -> bytes:
    """Build a full ListIdentity response for the given profile.

    Args:
        prof:           Profile dict from PROFILES.
        sender_context: 8-byte sender context echoed from the request.

    Returns:
        Complete encapsulation response (header + CPF).
    """
    body = build_identity_body(prof)

    cpf = struct.pack("<H", 1)                       # item count
    cpf += struct.pack("<H", CPF_ITEM_IDENTITY)      # item type
    cpf += struct.pack("<H", len(body))              # item length
    cpf += body

    sctx = (sender_context + b"\x00" * 8)[:8]
    header = struct.pack("<H", CMD_LIST_IDENTITY)    # command
    header += struct.pack("<H", len(cpf))            # length
    header += struct.pack("<I", 0)                   # session handle
    header += struct.pack("<I", 0)                   # status
    header += sctx                                   # sender context
    header += struct.pack("<I", 0)                   # options
    return header + cpf


# ======================================================================
# Packet Parser
# ======================================================================
def parse_encap_header(data: bytes):
    """Parse a 24-byte encapsulation header.

    Returns (command, length, session, status, sender_context, options)
    or raises ValueError if the buffer is too short.
    """
    if len(data) < ENIP_HEADER_LEN:
        raise ValueError(f"header too short: {len(data)} bytes")
    command, length, session, status = struct.unpack("<HHII", data[:12])
    sender_context = data[12:20]
    (options,) = struct.unpack("<I", data[20:24])
    return command, length, session, status, sender_context, options


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes, or fewer if the connection closes."""
    chunks = []
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            return b"".join(chunks)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ======================================================================
# Client Handler
# ======================================================================
def handle_client(conn, addr, profile: str, scan_delay_ms: int,
                  verbose: bool = False):
    """Handle a single EtherNet/IP client connection."""
    addr_str = f"{addr[0]}:{addr[1]}"
    prof = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])
    _detection_log.info("%s -> CONNECT (profile=%s)", addr_str, profile)

    try:
        while True:
            header = recv_exact(conn, ENIP_HEADER_LEN)
            if len(header) < ENIP_HEADER_LEN:
                break
            try:
                command, length, _s, _st, sctx, _o = parse_encap_header(header)
            except ValueError:
                break

            # Drain any declared payload so the stream stays framed.
            if length > 0:
                recv_exact(conn, length)

            if command == CMD_LIST_IDENTITY:
                _detection_log.info(
                    "%s -> ListIdentity (0x0063)", addr_str)
                if scan_delay_ms > 0:
                    time.sleep(scan_delay_ms / 1000.0)
                response = build_list_identity_response(prof, sctx)
                try:
                    conn.sendall(response)
                except OSError:
                    break
                if verbose:
                    print(f"  [{addr_str}] -> ListIdentity response "
                          f"({len(response)}B, name={prof['product_name']})")
            else:
                # Harmlessly ignore other commands (no reply).
                _detection_log.info(
                    "%s -> cmd 0x%04x (ignored)", addr_str, command)
    except (ConnectionResetError, ConnectionAbortedError):
        pass
    except Exception as e:  # noqa: BLE001 - keep the honeypot alive
        print(f"  [{addr_str}] Error: {type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ======================================================================
# Server
# ======================================================================
_shutdown = threading.Event()


def run_server(port: int = ENIP_DEFAULT_PORT, profile: str = DEFAULT_PROFILE,
               scan_delay_ms: int = DEFAULT_SCAN_DELAY_MS,
               verbose: bool = False):
    """Run the EtherNet/IP mock server until SIGTERM/Ctrl+C."""
    prof = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(1.0)
    except OSError as e:
        print(f"[FATAL] Cannot bind to 127.0.0.1:{port}: {e}")
        sys.exit(1)

    print(f"{'=' * 60}")
    print("  EtherNet/IP ListIdentity Honeypot Emulator")
    print(f"  Listening on:  127.0.0.1:{port}")
    print(f"  Profile:       {profile}")
    print(f"  Product Name:  {prof['product_name']}")
    print(f"  Vendor ID:     {prof['vendor_id']}  "
          f"Product Code: {prof['product_code']}")
    print(f"  Scan Delay:    {scan_delay_ms}ms")
    print(f"{'=' * 60}", flush=True)

    client_id = 0
    try:
        while not _shutdown.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client_id += 1
            threading.Thread(
                target=handle_client,
                args=(conn, addr, profile, scan_delay_ms, verbose),
                daemon=True,
                name=f"enip-client-{client_id}",
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def _handle_sigterm(signum, frame):
    _shutdown.set()


# ======================================================================
# Self-Test
# ======================================================================
def self_test():
    """Round-trip the builder/parser for every profile."""
    print("[SELF-TEST] EtherNet/IP ListIdentity packet round-trip...\n")
    for name, prof in PROFILES.items():
        resp = build_list_identity_response(prof, b"\xc1\xde\xbe\xd1")
        command, length, _s, _st, _sc, _o = parse_encap_header(resp)
        assert command == CMD_LIST_IDENTITY, name
        assert length == len(resp) - ENIP_HEADER_LEN, name

        # item count / item type at fixed offsets (0-based within resp)
        item_count = struct.unpack("<H", resp[24:26])[0]
        item_type = struct.unpack("<H", resp[26:28])[0]
        assert item_count == 1, name
        assert item_type == CPF_ITEM_IDENTITY, name

        # Identity fields at documented 1-based offsets (bin-compatible)
        vennum = struct.unpack("<H", resp[48:50])[0]
        devnum = struct.unpack("<H", resp[50:52])[0]
        pcode = struct.unpack("<H", resp[52:54])[0]
        rmaj, rmin = struct.unpack("BB", resp[54:56])
        serial = struct.unpack("<I", resp[58:62])[0]
        namelen = resp[62]
        pname = resp[63:63 + namelen].decode("ascii")
        state = resp[63 + namelen]

        assert vennum == prof["vendor_id"], name
        assert devnum == prof["device_type"], name
        assert pcode == prof["product_code"], name
        assert (rmaj, rmin) == prof["revision"], name
        assert serial == prof["serial"], name
        assert pname == prof["product_name"], (name, pname)
        assert state == prof["state"], name
        print(f"  [PASS] {name:13s} vendor={vennum} devtype={devnum} "
              f"code={pcode} rev={rmaj}.{rmin} "
              f"serial=0x{serial:08X} name='{pname}' state={state}")
    print("\n[SELF-TEST] All profiles passed.")


# ======================================================================
# Main
# ======================================================================
def main():
    parser = argparse.ArgumentParser(
        description="EtherNet/IP ListIdentity Honeypot-Grade Emulator",
    )
    parser.add_argument("--port", "-p", type=int, default=ENIP_DEFAULT_PORT,
                        help=f"TCP port (default: {ENIP_DEFAULT_PORT})")
    parser.add_argument("--profile", type=str, default=DEFAULT_PROFILE,
                        choices=sorted(PROFILES.keys()),
                        help=f"Device profile (default: {DEFAULT_PROFILE})")
    parser.add_argument("--scan-delay", type=int,
                        default=DEFAULT_SCAN_DELAY_MS, metavar="MS",
                        help="Simulated scan-cycle delay in ms")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable per-response logging")
    parser.add_argument("--self-test", action="store_true",
                        help="Run built-in packet self-test and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    signal.signal(signal.SIGTERM, _handle_sigterm)
    scan_delay = max(0, min(100, args.scan_delay))
    run_server(port=args.port, profile=args.profile,
               scan_delay_ms=scan_delay, verbose=args.verbose)


if __name__ == "__main__":
    main()
