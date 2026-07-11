#!/usr/bin/env python3
"""
ProConOS PLC Mock Server

Simulates a ProConOS PLC runtime on TCP port 20547.
Responds to the standard ProConOS discovery probe with PLC identification data.
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
log = logging.getLogger("proconos")

# Response payload containing ProConOS identification strings
# Format: 0xcc header + null-terminated ASCII strings at fixed offsets
def build_response():
    """Build the ProConOS identification response."""
    parts = bytearray()

    # Header
    parts.append(0xcc)
    parts.extend(b'\x01\x00\x0b\x00')
    parts.extend(b'\x00' * 8)

    # Extend to offset 13 with nulls
    while len(parts) < 13:
        parts.append(0x00)

    # Offset 13: Ladder Logic Runtime
    parts.extend(b'ProConOS V3.0.1040 Oct 29 2002')
    parts.append(0x00)

    # Extend to offset 45
    while len(parts) < 45:
        parts.append(0x00)

    # Offset 45: PLC Type
    parts.extend(b'ADAM5510KW 1.24 Build 005')
    parts.append(0x00)

    # Extend to offset 78
    while len(parts) < 78:
        parts.append(0x00)

    # Offset 78: Project Name
    parts.extend(b'510-projec')
    parts.append(0x00)

    # Boot Project
    parts.extend(b'510-projec')
    parts.append(0x00)

    # Project Source Code status
    parts.extend(b'Exist')
    parts.append(0x00)

    # Trailer padding
    parts.extend(b'\x00' * 16)

    return bytes(parts)


PROCONOS_RESPONSE = build_response()


def handle_client(conn, addr):
    """Handle a single ProConOS client connection."""
    log.info(f"Connection from {addr[0]}:{addr[1]}")

    try:
        data = conn.recv(4096)
        if not data:
            log.info(f"Client {addr} disconnected without sending data")
            return

        log.debug(f"Received ({len(data)} bytes): {data.hex()}")

        # Check if it's the standard ProConOS probe (starts with 0xcc)
        if len(data) > 0 and data[0] == 0xcc:
            log.info("Valid ProConOS probe received, sending identification")
            conn.sendall(PROCONOS_RESPONSE)
            log.debug(f"Sent ({len(PROCONOS_RESPONSE)} bytes): {PROCONOS_RESPONSE.hex()}")
        else:
            log.warning(f"Unknown probe format (first byte: 0x{data[0]:02x})")
            conn.sendall(b'\x00')

    except ConnectionResetError:
        log.warning(f"Connection reset by {addr}")
    except ConnectionAbortedError:
        log.warning(f"Connection aborted by {addr}")
    except Exception as e:
        log.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()


def main():
    host = '127.0.0.1'
    port = 20547

    # Allow override from command line
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    log.info(f"ProConOS mock server listening on {host}:{port}")
    log.info("Press Ctrl+C to stop")

    try:
        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        server.close()


if __name__ == '__main__':
    main()
