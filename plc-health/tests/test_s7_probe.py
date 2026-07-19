from plchealth.probes import s7
from plchealth.model import State


def test_s7_run(s7_run):
    h = s7.probe("127.0.0.1", s7_run, timeout=3.0)
    assert h.reachable and h.state is State.RUN


def test_s7_stop_with_diag(s7_stop):
    h = s7.probe("127.0.0.1", s7_stop, timeout=3.0)
    assert h.state is State.STOP
    assert any(f.source == "s7-diag" for f in h.faults)


def test_s7_unreachable():
    h = s7.probe("127.0.0.1", 1, timeout=0.3)
    assert h.reachable is False and h.state is State.UNREACHABLE
