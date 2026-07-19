from plchealth.probes import modbus
from plchealth.model import State


def test_healthy_modbus(modbus_healthy):
    h = modbus.probe("127.0.0.1", modbus_healthy, timeout=2.0)
    assert h.reachable and h.state is State.RUN and not h.faults


def test_fault_bit_set(modbus_faulted):
    h = modbus.probe("127.0.0.1", modbus_faulted, timeout=2.0,
                     status_reg=0, fault_bit=0)
    assert h.state is State.FAULT
    assert any(f.source == "modbus" for f in h.faults)


def test_modbus_exception(modbus_exception):
    h = modbus.probe("127.0.0.1", modbus_exception, timeout=2.0)
    assert h.state is State.FAULT
    assert h.faults[0].description == "Slave Device Failure"


def test_unreachable():
    h = modbus.probe("127.0.0.1", 1, timeout=0.3)
    assert h.reachable is False and h.state is State.UNREACHABLE
