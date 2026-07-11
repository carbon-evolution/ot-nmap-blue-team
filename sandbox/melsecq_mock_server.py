#!/usr/bin/env python3
"""
MELSEC-Q PLC Mock Server — TCP 5007.

Simulates a Mitsubishi MELSEC-Q Series PLC responding to MC protocol 3E frame
(binary mode) queries. Supports:

  - CPU type read  (command 0x0101) → "Q03UDECPU"
  - Model read     (command 0x0100) → "MELSEC-Q"
  - Version read   (command 0x0113) → "V1.20"

All 3E frames use:
  - 3-byte little-endian data length field
  - 3-byte timer field  (0x00 0x00 0x10 = 1000ms)
  - Response subheader 0xD000  for success
  - Response code 0x0000       for success

Handles multiple sequential requests on the same TCP connection per the
MC protocol's stateless request/response model.
"""

import socket
import struct
import sys
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("melsecq")

# ---------------------------------------------------------------------------
# 3E Frame constants
# ---------------------------------------------------------------------------
SUBHDR_REQUEST  = b"\x50\x00"   # binary mode request
SUBHDR_RESPONSE = b"\xD0\x00"   # binary mode response (success)
RESP_CODE_OK    = b"\x00\x00"   # success

FRAME_HDR_SZ    = 7             # subhdr(2) + net(1) + pc(1) + io(2) + station(1)

# Well-known commands
CMD_CPU_TYPE    = 0x0101
CMD_MODEL       = 0x0100
CMD_VERSION     = 0x0113

# Response data strings (padded to 16 bytes with nulls per MC protocol spec)
CPU_TYPE_STR  = b"Q03UDECPU\x00\x00\x00\x00\x00\x00\x00"   # 9+7 = 16
MODEL_STR     = b"MELSEC-Q\x00\x00\x00\x00\x00\x00\x00\x00" # 8+8 = 16
VERSION_STR   = b"V1.20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 5+11 = 16


# ---------------------------------------------------------------------------
# 3E frame builders / helpers
# ---------------------------------------------------------------------------

def pack_u24_le(val: int) -> bytes:
    """Pack an integer into 3 bytes, little-endian."""
    return bytes([val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF])


def unpack_u24_le(data: bytes, offset: int) -> int:
    """Unpack a 3-byte little-endian integer starting at *offset*."""
    return data[offset] + (data[offset + 1] << 8) + (data[offset + 2] << 16)


def parse_3e_request(data: bytes):
    """Parse an incoming 3E binary-mode request frame.

    Returns (network, pc, io_bytes, station, command, subcommand, payload)
    or raises ValueError if the frame is invalid.
    """
    if len(data) < FRAME_HDR_SZ + 6:
        raise ValueError(f"Frame too short: {len(data)} bytes")

    if data[:2] != SUBHDR_REQUEST:
        raise ValueError(f"Bad request subheader: {data[:2].hex()}")

    network = data[2]
    pc      = data[3]
    io      = data[4:6]
    station = data[6]

    dlen  = unpack_u24_le(data, 7)     # 3-byte data length
    if len(data) < FRAME_HDR_SZ + 3 + dlen:
        raise ValueError(
            f"Frame data truncated: header+len says {FRAME_HDR_SZ + 3 + dlen}B "
            f"but got {len(data)}B"
        )

    # Payload starts after the 3-byte length field
    payload = data[FRAME_HDR_SZ + 3: FRAME_HDR_SZ + 3 + dlen]

    if len(payload) < 7:   # timer(3) + cmd(2) + subcmd(2)
        raise ValueError(f"Payload too short: {len(payload)} bytes")

    # timer = payload[0:3]   (we don't interpret it server-side)
    cmd     = struct.unpack_from("<H", payload, 3)[0]
    subcmd  = struct.unpack_from("<H", payload, 5)[0]
    pldata  = payload[7:]   # command-specific data

    return network, pc, io, station, cmd, subcmd, pldata


def build_3e_response(network: int, pc: int, io: bytes, station: int,
                      response_data: bytes) -> bytes:
    """Build a complete 3E binary-mode response frame.

    The routing fields are echoed from the request.  *response_data* is
    placed after the response code (0x0000 = success).
    """
    # Payload after length field = response code + response data
    payload = RESP_CODE_OK + response_data

    frame = (
        SUBHDR_RESPONSE          # subheader (2)
        + bytes([network])       # network
        + bytes([pc])            # PC
        + io                     # I/O (2)
        + bytes([station])       # station
        + pack_u24_le(len(payload))   # data length (3)
        + payload                # resp_code + data
    )
    return frame


# ---------------------------------------------------------------------------
# Per-command response builders
# ---------------------------------------------------------------------------

def handle_cpu_type_read(network: int, pc: int, io: bytes,
                         station: int) -> bytes:
    """CPU type read (0x0101) → 16-byte CPU type string."""
    log.info("  → CPU type read: returning %s", CPU_TYPE_STR.rstrip(b"\x00").decode())
    return build_3e_response(network, pc, io, station, CPU_TYPE_STR)


def handle_model_read(network: int, pc: int, io: bytes,
                      station: int) -> bytes:
    """Model read (0x0100) → 16-byte model name string."""
    log.info("  → Model read: returning %s", MODEL_STR.rstrip(b"\x00").decode())
    return build_3e_response(network, pc, io, station, MODEL_STR)


def handle_version_read(network: int, pc: int, io: bytes,
                        station: int) -> bytes:
    """Version read (0x0113) → 16-byte firmware version string."""
    log.info("  → Version read: returning %s", VERSION_STR.rstrip(b"\x00").decode())
    return build_3e_response(network, pc, io, station, VERSION_STR)


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

COMMAND_MAP = {
    CMD_CPU_TYPE: handle_cpu_type_read,
    CMD_MODEL:    handle_model_read,
    CMD_VERSION:  handle_version_read,
}


def handle_client(conn, addr):
    """Process all requests from a single client connection."""
    log.info("Connection from %s:%d", addr[0], addr[1])
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                log.info("Client %s closed connection", addr[0])
                break

            log.debug("Rx (%d B): %s", len(data), data.hex())

            try:
                network, pc, io, station, cmd, subcmd, pldata = \
                    parse_3e_request(data)
            except ValueError as exc:
                log.warning("Parse error: %s", exc)
                break

            log.info(
                "Cmd=0x%04x Subcmd=0x%04x net=0x%02x pc=0x%02x "
                "io=%s station=0x%02x",
                cmd, subcmd, network, pc, io.hex(), station,
            )

            handler = COMMAND_MAP.get(cmd)
            if handler:
                resp = handler(network, pc, io, station)
            else:
                log.warning("Unsupported command 0x%04x (subcmd 0x%04x)",
                            cmd, subcmd)
                # Return a 3E error frame (end code 0x5FF0 = command reject)
                err_payload = b"\xF0\x5F"   # end code (LE)
                resp = build_3e_response(network, pc, io, station, err_payload)

            conn.sendall(resp)
            log.debug("Tx (%d B): %s", len(resp), resp.hex())

    except ConnectionResetError:
        log.warning("Connection reset by %s", addr[0])
    except ConnectionAbortedError:
        log.warning("Connection aborted by %s", addr[0])
    except Exception as exc:
        log.error("Error handling %s: %s", addr[0], exc)
    finally:
        conn.close()
        log.info("Connection from %s closed", addr[0])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5007

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    log.info("MELSEC-Q mock server listening on %s:%d", host, port)
    log.info("Press Ctrl+C to stop")

    try:
        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        server.close()


if __name__ == "__main__":
    main()
