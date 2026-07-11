#!/usr/bin/env python3
"""
Red Lion Controls Crimson v3 Mock Server

Simulates a Red Lion Controls HMI/PLC device on TCP port 789 (Crimson v3).
Responds to the standard 16-byte zero-filled identification probe with
device identity data including manufacturer, model, and firmware version.

Usage:
    python3 redlion_mock_server.py
    python3 redlion_mock_server.py 127.0.0.1 789
"""

import socket
import struct
import sys
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger("redlion")


def build_response():
    """Build the Red Lion Crimson v3 identification response.

    The response is a binary blob containing printable ASCII identity
    strings at fixed offsets, mimicking the structure of real Red Lion
    device responses seen on TCP 789.

    Structure:
      [0..3]     Fixed header bytes
      [4..7]     Response length (placeholder)
      [8..15]    Reserved / zero padding
      [16]       Start of ASCII identity block
      [16..35]   Manufacturer: "Red Lion Controls\0"
      [36..55]   Model: "G310C2\0"
      [56..79]   Firmware: "Crimson 3.2\0"
      [80..127]  Extra padding / zero fill
    """
    parts = bytearray()

    # Header: fixed signature bytes
    parts.extend(b'\x06\x00\x01\x00')

    # Response payload length placeholder (4 bytes)
    parts.extend(b'\x00\x00\x00\x00')

    # Reserved / zero padding
    parts.extend(b'\x00' * 8)

    # --- ASCII identity block ---

    # Offset 16: Manufacturer
    parts.extend(b'Red Lion Controls')
    parts.append(0x00)

    # Pad to offset 36
    while len(parts) < 36:
        parts.append(0x00)

    # Offset 36: Model number
    parts.extend(b'G310C2')
    parts.append(0x00)

    # Pad to offset 56
    while len(parts) < 56:
        parts.append(0x00)

    # Offset 56: Firmware version
    parts.extend(b'Crimson 3.2')
    parts.append(0x00)

    # Pad to the end
    while len(parts) < 128:
        parts.append(0x00)

    # Now write the actual payload length at bytes 4-7
    payload_len = len(parts) - 8
    struct.pack_into('>I', parts, 4, payload_len)

    return bytes(parts)


REDLION_RESPONSE = build_response()


def handle_client(conn, addr):
    """Handle a single Red Lion client connection."""
    log.info(f"Connection from {addr[0]}:{addr[1]}")

    try:
        data = conn.recv(4096)
        if not data:
            log.info(f"Client {addr} disconnected without sending data")
            return

        log.info(f"Received ({len(data)} bytes): {data.hex()}")

        # Check for the 16-byte zero-filled identification probe
        if len(data) >= 16 and all(b == 0 for b in data[:16]):
            log.info("Valid identification probe detected, sending device info")
            conn.sendall(REDLION_RESPONSE)
            log.info(f"Sent ({len(REDLION_RESPONSE)} bytes): {REDLION_RESPONSE.hex()}")

            # Log the printable contents
            log.info(f"  Manufacturer: Red Lion Controls")
            log.info(f"  Model: G310C2")
            log.info(f"  Firmware: Crimson 3.2")
        else:
            log.warning(f"Unexpected probe format (first 16 bytes: {data[:16].hex()})")
            conn.sendall(b'\x00')

    except ConnectionResetError:
        log.warning(f"Connection reset by {addr}")
    except ConnectionAbortedError:
        log.warning(f"Connection aborted by {addr}")
    except TimeoutError:
        log.warning(f"Connection timed out for {addr}")
    except Exception as e:
        log.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()


def main():
    host = '127.0.0.1'
    port = 789

    # Allow override from command line
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
    except PermissionError:
        log.error(f"Cannot bind to port {port} — need root on Unix for ports < 1024")
        log.info(f"Try: sudo python3 {sys.argv[0]} {host} {port}")
        sys.exit(1)
    except OSError as e:
        log.error(f"Failed to bind: {e}")
        sys.exit(1)

    server.listen(5)
    log.info(f"Red Lion Crimson v3 mock server listening on {host}:{port}")
    log.info("Press Ctrl+C to stop")

    try:
        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        server.close()
        log.info("Server stopped")


if __name__ == '__main__':
    main()
