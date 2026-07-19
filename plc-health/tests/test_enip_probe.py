from plchealth.probes import enip
from plchealth.model import State


def test_healthy_enip(enip_healthy):
    h = enip.probe("127.0.0.1", enip_healthy, timeout=2.0)
    assert h.reachable and h.state is State.RUN and not h.faults
    assert h.identity.get("state_name") == "Running/Idle"


def test_faulted_enip(enip_faulted):
    h = enip.probe("127.0.0.1", enip_faulted, timeout=2.0)
    assert h.state is State.FAULT
    assert any("Fault" in f.description for f in h.faults)


def test_unreachable_enip():
    h = enip.probe("127.0.0.1", 1, timeout=0.3)
    assert h.reachable is False and h.state is State.UNREACHABLE
