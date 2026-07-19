"""Low-level socket byte helpers shared by probes."""
import socket


def recv_exactly(sock: socket.socket, n: int, timeout: float) -> bytes:
    """Read exactly n bytes or raise ConnectionError if the peer closes early."""
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(buf)} of {n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def hexs(b: bytes) -> str:
    return b.hex()
