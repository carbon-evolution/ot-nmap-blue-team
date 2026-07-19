import socket
import threading

from plchealth import framing


def test_recv_exactly_reassembles_chunks():
    a, b = socket.socketpair()
    try:
        def send():
            b.sendall(b"AB")
            b.sendall(b"CD")
        threading.Thread(target=send).start()
        assert framing.recv_exactly(a, 4, timeout=2.0) == b"ABCD"
    finally:
        a.close(); b.close()


def test_recv_exactly_raises_on_short_close():
    a, b = socket.socketpair()
    try:
        b.sendall(b"AB")
        b.close()
        try:
            framing.recv_exactly(a, 4, timeout=2.0)
            assert False, "expected ConnectionError"
        except (ConnectionError, OSError):
            pass
    finally:
        a.close()


def test_hexs():
    assert framing.hexs(b"\x00\xff") == "00ff"
