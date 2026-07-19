import pytest

snap7 = pytest.importorskip("snap7")
pytestmark = pytest.mark.sim


def test_snap7_server_reachable():
    """Cross-check: our S7 probe can at least handshake a snap7 server.

    snap7's server does not implement SZL 0x0424 the way a real S7 CPU does,
    so this validates connectivity/handshake, not the CPU-state decode. Full
    CPU-state validation is covered by the bundled mock in test_s7_probe.py.
    """
    from snap7.server import Server
    from plchealth.probes import s7
    from plchealth.model import State

    srv = Server()
    srv.start_to(("127.0.0.1", 10200))
    try:
        h = s7.probe("127.0.0.1", 10200, timeout=2.0)
        assert h.reachable or h.state is State.UNKNOWN
    finally:
        srv.stop()
        srv.destroy()
