#!/usr/bin/env python3
"""
OPC UA Mock Server — TCP 4840

Implements the OPC UA Binary handshake (HEL → ACK) for testing nmap NSE
discovery scripts.  Logs all sent/received data in hex.

OPC UA HEL message structure (all little-endian):
  byte   0-2: 'HEL'               ASCII message type
  byte     3: 0x00                Reserved
  byte   4-7: message_length      Total message size (uint32)
  byte  8-11: protocol_version    Protocol version (uint32)
  byte 12-15: receive_buffer_size (uint32)
  byte 16-19: send_buffer_size    (uint32)
  byte 20-23: max_message_length  (uint32)
  byte 24-27: max_chunk_count     (uint32)
  byte 28-31: endpoint_url_length (uint32) + URL data if length > 0

OPC UA ACK response structure:
  byte   0-2: 'ACK'               ASCII message type
  byte     3: 0x00                Reserved
  byte   4-7: message_length      Total message size (uint32)
  byte  8-11: protocol_version    Responded protocol version (uint32)
  byte 12-15: receive_buffer_size (uint32)
  byte 16-19: send_buffer_size    (uint32)
  byte 20-23: max_message_length  (uint32)
  byte 24-27: max_chunk_count     (uint32)
"""

import socket
import struct
import sys
from datetime import datetime

# ── Constants ────────────────────────────────────────────────────────────────
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 4840

# Default ACK parameters
ACK_PROTOCOL_VERSION = 0
ACK_RECV_BUFFER_SIZE = 65535
ACK_SEND_BUFFER_SIZE = 65535
ACK_MAX_MESSAGE_LEN  = 65536
ACK_MAX_CHUNK_COUNT  = 0

# ── Hex dump helper ──────────────────────────────────────────────────────────

def hex_dump(data: bytes, label: str = "") -> str:
    """Format bytes as a readable hex dump with ASCII sidebar."""
    lines = []
    if label:
        lines.append(f"─── {label} ({len(data)} bytes) ───")
    else:
        lines.append(f"─── {len(data)} bytes ───")

    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part for alignment
        if len(chunk) < 16:
            hex_part = hex_part.ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part}  |{ascii_part}|")

    return "\n".join(lines)


# ── OPC UA message builders / parsers ────────────────────────────────────────

def build_ack_message(
    protocol_version: int = ACK_PROTOCOL_VERSION,
    recv_buffer_size: int = ACK_RECV_BUFFER_SIZE,
    send_buffer_size: int = ACK_SEND_BUFFER_SIZE,
    max_message_len: int = ACK_MAX_MESSAGE_LEN,
    max_chunk_count: int = ACK_MAX_CHUNK_COUNT,
) -> bytes:
    """Build an OPC UA Binary ACK (Acknowledge) message.

    Returns:
        28-byte ACK message ready to send over the wire.
    """
    message_length = 28  # fixed size for ACK

    ack = b"ACK"                         # bytes 0-2: message type
    ack += b"\x00"                       # byte 3: reserved / final byte of 4-char type
    ack += struct.pack("<I", message_length)   # bytes 4-7
    ack += struct.pack("<I", protocol_version) # bytes 8-11
    ack += struct.pack("<I", recv_buffer_size) # bytes 12-15
    ack += struct.pack("<I", send_buffer_size) # bytes 16-19
    ack += struct.pack("<I", max_message_len)  # bytes 20-23
    ack += struct.pack("<I", max_chunk_count)  # bytes 24-27

    assert len(ack) == 28, f"ACK message should be 28 bytes, got {len(ack)}"
    return ack


def parse_hello_message(data: bytes) -> dict:
    """Parse an OPC UA Binary HEL (Hello) message.

    Args:
        data: Raw bytes received from the client.

    Returns:
        Dictionary with parsed fields, or error info if parsing fails.
    """
    result = {"valid": False, "fields": {}, "error": None}

    if len(data) < 32:
        result["error"] = f"Too short: {len(data)} bytes (minimum 32)"
        return result

    # Validate HEL tag
    if data[0:3] != b"HEL":
        result["error"] = (
            f"Invalid message type tag: "
            f"got {data[0:3]!r} (0x{data[0:3].hex()}), expected 'HEL'"
        )
        return result

    try:
        pos = 4  # skip "HEL\0"
        message_length      = struct.unpack_from("<I", data, pos)[0]; pos += 4
        protocol_version    = struct.unpack_from("<I", data, pos)[0]; pos += 4
        receive_buffer_size = struct.unpack_from("<I", data, pos)[0]; pos += 4
        send_buffer_size    = struct.unpack_from("<I", data, pos)[0]; pos += 4
        max_message_length  = struct.unpack_from("<I", data, pos)[0]; pos += 4
        max_chunk_count     = struct.unpack_from("<I", data, pos)[0]; pos += 4
        endpoint_url_length = struct.unpack_from("<I", data, pos)[0]; pos += 4

        endpoint_url = ""
        if endpoint_url_length > 0 and pos + endpoint_url_length <= len(data):
            endpoint_url = data[pos : pos + endpoint_url_length].decode("utf-8", errors="replace")

        result["valid"] = True
        result["fields"] = {
            "message_length":      message_length,
            "protocol_version":    protocol_version,
            "receive_buffer_size": receive_buffer_size,
            "send_buffer_size":    send_buffer_size,
            "max_message_length":  max_message_length,
            "max_chunk_count":     max_chunk_count,
            "endpoint_url_length": endpoint_url_length,
            "endpoint_url":        endpoint_url,
        }
    except struct.error as e:
        result["error"] = f"Struct unpack failed: {e}"

    return result


# ── Client handler ───────────────────────────────────────────────────────────

def handle_client(client_sock: socket.socket, addr: tuple) -> None:
    """Handle a single OPC UA client connection."""
    client_sock.settimeout(10.0)
    remote = f"{addr[0]}:{addr[1]}"
    print(f"\n[+] Connection from {remote}")

    try:
        # Read HEL message (minimum 32 bytes, but read up to 4K)
        data = client_sock.recv(4096)
        if not data:
            print(f"[-] {remote}: Connection closed (no data received)")
            return

        print(hex_dump(data, label=f"RECV from {remote}"))

        # Parse the HEL message
        parsed = parse_hello_message(data)
        if not parsed["valid"]:
            print(f"[-] {remote}: Invalid HEL — {parsed['error']}")
            return

        fields = parsed["fields"]
        print(f"\n  >>> PARSED HEL <<<")
        print(f"    Message length:      {fields['message_length']}")
        print(f"    Protocol version:    {fields['protocol_version']}")
        print(f"    Receive buffer size: {fields['receive_buffer_size']}")
        print(f"    Send buffer size:    {fields['send_buffer_size']}")
        print(f"    Max message length:  {fields['max_message_length']}")
        print(f"    Max chunk count:     {fields['max_chunk_count']}")
        print(f"    Endpoint URL length: {fields['endpoint_url_length']}")
        if fields["endpoint_url"]:
            print(f"    Endpoint URL:        {fields['endpoint_url']}")

        # Build and send ACK response
        ack = build_ack_message(
            protocol_version=ACK_PROTOCOL_VERSION,
            recv_buffer_size=ACK_RECV_BUFFER_SIZE,
            send_buffer_size=ACK_SEND_BUFFER_SIZE,
            max_message_len=ACK_MAX_MESSAGE_LEN,
            max_chunk_count=ACK_MAX_CHUNK_COUNT,
        )

        print(f"\n  >>> SENDING ACK <<<")
        print(f"    Protocol version:    {ACK_PROTOCOL_VERSION}")
        print(f"    Receive buffer size: {ACK_RECV_BUFFER_SIZE}")
        print(f"    Send buffer size:    {ACK_SEND_BUFFER_SIZE}")
        print(f"    Max message length:  {ACK_MAX_MESSAGE_LEN}")
        print(f"    Max chunk count:     {ACK_MAX_CHUNK_COUNT}")
        print(hex_dump(ack, label=f"SEND to {remote}"))

        client_sock.sendall(ack)

        # After ACK, wait a moment then close — we are a mock discovery server
        # In a real OPC UA server the next step would be an OpenSecureChannel
        # (OPN) message, but for NSE discovery testing we stop here.
        print(f"[*] {remote}: Handshake complete. Waiting for additional data...")

        try:
            extra = client_sock.recv(4096)
            if extra:
                print(hex_dump(extra, label=f"EXTRA RECV from {remote}"))
                # The client might send an OPN (OpenSecureChannel) message.
                # Peek at the type tag:
                if len(extra) >= 3:
                    msg_type = extra[0:3].decode("ascii", errors="replace")
                    print(f"    (message type: '{msg_type}')")
        except socket.timeout:
            print(f"[-] {remote}: No additional data (timeout)")

    except socket.timeout:
        print(f"[-] {remote}: Socket timeout while reading HEL")
    except ConnectionResetError:
        print(f"[-] {remote}: Connection reset by peer")
    except ConnectionAbortedError:
        print(f"[-] {remote}: Connection aborted")
    except Exception as e:
        print(f"[-] {remote}: Error: {type(e).__name__}: {e}")
    finally:
        try:
            client_sock.close()
        except OSError:
            pass
        print(f"[*] {remote}: Connection closed\n")


# ── Main server loop ─────────────────────────────────────────────────────────

def main():
    # Create TCP socket with SO_REUSEADDR for quick restarts
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(None)  # blocking accept

    try:
        server.bind((LISTEN_HOST, LISTEN_PORT))
        server.listen(5)
    except PermissionError:
        print(
            f"ERROR: Binding to {LISTEN_HOST}:{LISTEN_PORT} requires root "
            f"privileges.\n"
            f"  Try running with: sudo {sys.argv[0]}\n"
            f"  Or use a non-privileged port: edit LISTEN_PORT in the script."
        )
        sys.exit(1)
    except OSError as e:
        print(f"ERROR: Failed to bind: {e}")
        sys.exit(1)

    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║            OPC UA Mock Discovery Server                     ║
╠══════════════════════════════════════════════════════════════╣
║  Listening on  {LISTEN_HOST}:{LISTEN_PORT}                       ║
║  PID:          {os.getpid():<39}║
║  Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<25}║
║                                                              ║
║  Sending ACK:  proto_ver={ACK_PROTOCOL_VERSION},               ║
║                recv_buf={ACK_RECV_BUFFER_SIZE}, send_buf={ACK_SEND_BUFFER_SIZE},           ║
║                max_msg={ACK_MAX_MESSAGE_LEN}, max_chunks={ACK_MAX_CHUNK_COUNT}               ║
║                                                              ║
║  Press Ctrl+C to stop                                        ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

    try:
        while True:
            client_sock, addr = server.accept()
            handle_client(client_sock, addr)
    except KeyboardInterrupt:
        print(f"\n[*] Shutting down (received Ctrl+C)...")
    finally:
        server.close()
        print("[*] Server stopped.")


if __name__ == "__main__":
    import os
    main()
