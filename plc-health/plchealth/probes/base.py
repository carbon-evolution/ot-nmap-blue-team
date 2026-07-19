"""Shared probe helpers: TCP connect with a uniform unreachable result."""
import socket
from contextlib import contextmanager

from plchealth.model import PLCHealth


@contextmanager
def tcp(host: str, port: int, timeout: float):
    """Yield a connected socket, or raise OSError the caller maps to UNREACHABLE."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        yield sock
    finally:
        try:
            sock.close()
        except OSError:
            pass


def unreachable(host, port, proto) -> PLCHealth:
    return PLCHealth.unreachable(host, port, proto)
