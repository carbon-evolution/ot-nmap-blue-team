#!/usr/bin/env python3
"""
FF HSE (Foundation Fieldbus High Speed Ethernet) Mock Server.

Simulates a Foundation Fieldbus HSE device responding on TCP ports 1089-1091.
Useful for testing the ff-hse-discover-improved.nse Nmap NSE script.

Ports:
  1089 - HSE Management Agent (MA)
  1090 - HSE System Management (SM) primary
  1091 - HSE System Management (SM) alternate

The server presents realistic HSE protocol responses including device
identification strings, vendor info, and protocol version numbers.

Usage:
  python3 ffhse_mock_server.py              # listen on default ports
  python3 ffhse_mock_server.py --port 1089   # single port only
  python3 ffhse_mock_server.py --verbose     # verbose hex logging

Press Ctrl+C to stop.
"""

import argparse
import logging
import socket
import struct
import sys
import time

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ffhse-mock")


# ─── Protocol Constants ─────────────────────────────────────────────────────

# HSE SM Protocol versions and service codes
SM_PROTO_VER = 0x01
SM_SERVICE_IDENTIFY = 0x01
SM_SERVICE_STATUS = 0x04
SM_STATUS_SUCCESS = 0x00

# HSE Management Agent protocol discriminator
MA_PROTO_DISCRIMINATOR = 0x90
MA_MSG_GET_IDENTIFICATION = 0x01
MA_MSG_IDENTIFICATION_RESP = 0x81


# ─── Device Identity ────────────────────────────────────────────────────────

# Change these to simulate different FF HSE devices.
DEVICE_ID = "ACME-FF-HSE-24601"
VENDOR_NAME = "Fieldbus Foundation"
DEVICE_TAG = "FIC-101"
HSE_VERSION = "1.2"
SOFTWARE_REV = "3.0.1"
DEVICE_TYPE = "FF_HSE_Device"
STACK_VERSION = "FF_HSE_Stack_v2.1"
MAC_ADDRESS = "00:1B:44:11:3A:B7"


# ─── Response Builders ─────────────────────────────────────────────────────

def build_sm_identify_response() -> bytes:
    """Build a realistic HSE SM_Identify response.

    The SM_Identify response structure:
      Bytes 0-1: Version + Service code
      Byte 2: Status (0 = success)
      Byte 3: Reserved/Flags
      Then null-terminated ASCII strings for device info.
    """
    header = struct.pack("!BBBB",
        SM_PROTO_VER,           # Protocol version
        SM_SERVICE_IDENTIFY,    # Service code (echoed back)
        SM_STATUS_SUCCESS,      # Status
        0x00,                   # Reserved
    )
    # Null-terminated device info strings
    fields = [
        DEVICE_ID.encode(),
        VENDOR_NAME.encode(),
        DEVICE_TAG.encode(),
        HSE_VERSION.encode(),
        SOFTWARE_REV.encode(),
        DEVICE_TYPE.encode(),
        STACK_VERSION.encode(),
    ]
    body = b"\x00".join(fields) + b"\x00"
    return header + body


def build_ma_identification_response(txn_id: int = 1) -> bytes:
    """Build an HSE Management Agent identification response.

    The MA response structure:
      Byte 0: Protocol discriminator (0x90 = HSE MA)
      Byte 1: Response type (0x81 = response with bit 7 set)
      Bytes 2-3: Transaction ID (echoed from request)
      Then null-terminated strings for device info.
    """
    header = struct.pack("!BBHH",
        MA_PROTO_DISCRIMINATOR,        # Protocol discriminator
        MA_MSG_IDENTIFICATION_RESP,    # Response type
        txn_id & 0xFFFF,               # Transaction ID (echoed)
        0x0000,                        # Reserved / flags
    )
    fields = [
        DEVICE_ID.encode(),
        VENDOR_NAME.encode(),
        DEVICE_TYPE.encode(),
        HSE_VERSION.encode(),
        STACK_VERSION.encode(),
    ]
    body = b"\x00".join(fields) + b"\x00"
    return header + body


def build_ma_banner() -> bytes:
    """Build an initial banner that some HSE devices send on connect.

    This banner mimics devices that announce themselves immediately
    after TCP connection is established (e.g., some legacy HSE
    interfaces). Contains human-readable identification strings.
    """
    lines = [
        f"FF_HSE Device: {DEVICE_ID}",
        f"Vendor: {VENDOR_NAME}",
        f"Device Tag: {DEVICE_TAG}",
        f"HSE Version: {HSE_VERSION}",
        f"Software Rev: {SOFTWARE_REV}",
        f"Stack: {STACK_VERSION}",
        f"MAC: {MAC_ADDRESS}",
    ]
    payload = "\r\n".join(lines) + "\r\n"
    return payload.encode()


# ─── Hex Dump Utility ──────────────────────────────────────────────────────

def hex_dump(data: bytes, label: str = "") -> str:
    """Return a formatted hex dump of the data.

    Shows both hexadecimal and ASCII representation, similar to
    Wireshark/xxd output.
    """
    output = []
    if label:
        output.append(f"─── {label} ({len(data)} bytes) ───")
    else:
        output.append(f"─── Data ({len(data)} bytes) ───")

    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex_part for consistent alignment
        if len(chunk) < 16:
            hex_part += "   " * (16 - len(chunk))
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        output.append(f"  {offset:04x}: {hex_part}  |{ascii_part}|")

    return "\n".join(output)


# ─── Connection Handler ─────────────────────────────────────────────────────

def handle_connection(conn: socket.socket, addr: tuple, port: int, verbose: bool):
    """Handle a single client connection to an HSE port.

    Implements the protocol behavior:
    1. Accept connection
    2. Send a brief banner (some HSE devices do this)
    3. Wait for client to send a probe
    4. Respond with appropriate HSE protocol response
    5. Log everything in hex

    Args:
        conn: The connected socket.
        addr: Client address (ip, port).
        port: The local port this connection came in on.
        verbose: Enable verbose hex logging.
    """
    client_ip, client_port = addr
    service = {
        1089: "HSE Management Agent",
        1090: "HSE System Management (primary)",
        1091: "HSE System Management (alternate)",
    }.get(port, f"port {port}")

    log.info("Connection from %s:%d on %s [%d]",
             client_ip, client_port, service, port)

    try:
        with conn:
            # ── Step 1: Send banner ───────────────────────────────────
            # Some HSE devices send an identification banner immediately
            # upon TCP connection. This helps the NSE script detect the
            # device even without sending a probe.
            banner = build_ma_banner()
            conn.sendall(banner)
            if verbose:
                log.info("Sent banner (%d bytes) to %s:%d",
                         len(banner), client_ip, client_port)
                for line in hex_dump(banner, "TX Banner").split("\n"):
                    log.info("  %s", line)
            else:
                log.info("Sent banner (%d bytes) to %s:%d",
                         len(banner), client_ip, client_port)

            # ── Step 2: Wait for client data ──────────────────────────
            conn.settimeout(5.0)
            try:
                data = conn.recv(4096)
            except socket.timeout:
                log.info("Timeout waiting for probe from %s:%d (client "
                         "may only be banner-grabbing)",
                         client_ip, client_port)
                return

            if not data:
                log.info("Client %s:%d closed connection", client_ip, client_port)
                return

            if verbose:
                for line in hex_dump(data, "RX Probe").split("\n"):
                    log.info("  %s", line)
            else:
                log.info("Received %d bytes from %s:%d",
                         len(data), client_ip, client_port)

            # ── Step 3: Build and send response ───────────────────────
            # Determine which response to send based on the port and
            # the content of the probe.
            response = None

            if port == 1089:
                # HSE Management Agent port
                # Check for MA probe (protocol discriminator 0x90)
                if len(data) >= 1 and data[0] == MA_PROTO_DISCRIMINATOR:
                    # Extract transaction ID from probe if present
                    txn_id = 1
                    if len(data) >= 4:
                        txn_id = struct.unpack("!H", data[2:4])[0]
                    response = build_ma_identification_response(txn_id)
                    log.info("Sending MA identification response "
                             "(txn_id=%d)", txn_id)
                else:
                    # Unknown probe format; send generic MA response
                    response = build_ma_identification_response()
                    log.info("Unknown probe format, sending generic "
                             "MA identification response")

            elif port in (1090, 1091):
                # HSE System Management ports
                # Check for SM_Identify probe (version 0x01, service 0x01)
                if len(data) >= 2 and data[0] == SM_PROTO_VER \
                        and data[1] == SM_SERVICE_IDENTIFY:
                    response = build_sm_identify_response()
                    log.info("Sending SM_Identify response")
                else:
                    # Unknown probe; send SM status response or
                    # generic identify response
                    response = build_sm_identify_response()
                    log.info("Unknown SM probe, sending SM_Identify "
                             "response anyway")

            if response:
                conn.sendall(response)
                if verbose:
                    for line in hex_dump(response, "TX Response").split("\n"):
                        log.info("  %s", line)
                else:
                    log.info("Sent %d-byte response to %s:%d",
                             len(response), client_ip, client_port)

    except Exception as e:
        log.error("Error handling connection from %s:%d: %s",
                  client_ip, client_port, e)


# ─── Server ─────────────────────────────────────────────────────────────────

def start_server(ports: list, verbose: bool):
    """Start the FF HSE mock server on the specified ports.

    Creates a listening socket for each port and accepts connections
    in a loop, dispatching each to a handler.

    Args:
        ports: List of TCP port numbers to listen on.
        verbose: Enable verbose hex logging.
    """
    sockets = []
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            sock.settimeout(1.0)  # Allow periodic checks for Ctrl+C
            sockets.append((port, sock))
            log.info("Listening on 0.0.0.0:%d [%s]",
                     port,
                     {1089: "HSE MA", 1090: "HSE SM", 1091: "HSE SM-alt"}
                     .get(port, "HSE"))

        port_list = ", ".join(str(p) for p in ports)
        log.info("FF HSE mock server running on port(s): %s", port_list)
        log.info("Press Ctrl+C to stop.")
        log.info("")

        while True:
            for port_num, sock in sockets:
                try:
                    conn, addr = sock.accept()
                    handle_connection(conn, addr, port_num, verbose)
                except socket.timeout:
                    continue
                except OSError as e:
                    # Non-critical accept errors (e.g., connection reset
                    # before accept)
                    log.debug("Accept error on port %d: %s", port_num, e)
                    continue

    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        for port_num, sock in sockets:
            sock.close()
        log.info("All ports closed.")


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="FF HSE (Foundation Fieldbus High Speed Ethernet) Mock Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s                          # all 3 ports (1089-1091)\n"
            "  %(prog)s --port 1089               # single port\n"
            "  %(prog)s --port 1089 --port 1090   # two ports\n"
            "  %(prog)s --verbose                 # hex dump all traffic\n"
        ),
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        action="append",
        choices=[1089, 1090, 1091],
        help="TCP port to listen on (may specify multiple; default: 1089 1090 1091)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose hex dump logging",
    )
    args = parser.parse_args()

    ports = args.port if args.port else [1089, 1090, 1091]

    # Deduplicate and sort
    ports = sorted(set(ports))

    if not ports:
        log.error("No valid ports specified. Use --port 1089, --port 1090, "
                  "or --port 1091.")
        sys.exit(1)

    # Set verbose logging format
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    start_server(ports, args.verbose)


if __name__ == "__main__":
    main()
