from plchealth import poller
from plchealth.model import State


def test_explicit_modbus(modbus_healthy):
    h = poller.poll("127.0.0.1", proto="modbus", port=modbus_healthy, timeout=2.0)
    assert h.proto == "modbus" and h.reachable


def test_auto_detects_open_port(enip_healthy):
    # auto should find the open ENIP port among the candidates.
    h = poller.poll("127.0.0.1", proto="auto", timeout=1.0,
                    ports={"modbus": 1, "s7": 1, "enip": enip_healthy})
    assert h.proto == "enip" and h.reachable


def test_auto_none_open():
    h = poller.poll("127.0.0.1", proto="auto", timeout=0.3,
                    ports={"modbus": 1, "s7": 1, "enip": 1})
    assert h.reachable is False and h.state is State.UNREACHABLE
