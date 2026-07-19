import json

from plchealth.model import PLCHealth, Fault, State


def test_healthy_when_run_and_no_faults():
    h = PLCHealth(host="10.0.0.1", port=502, proto="modbus",
                  reachable=True, state=State.RUN, faults=[])
    assert h.healthy() is True


def test_not_healthy_with_fault_present():
    h = PLCHealth(host="10.0.0.1", port=502, proto="modbus",
                  reachable=True, state=State.RUN,
                  faults=[Fault(code="0x04", description="Slave Device Failure",
                                source="modbus")])
    assert h.healthy() is False


def test_not_healthy_when_stopped():
    h = PLCHealth(host="10.0.0.1", port=102, proto="s7",
                  reachable=True, state=State.STOP, faults=[])
    assert h.healthy() is False


def test_unreachable_helper():
    h = PLCHealth.unreachable("10.0.0.9", 44818, "enip")
    assert h.reachable is False and h.state is State.UNREACHABLE
    assert h.healthy() is False


def test_to_dict_is_json_serializable():
    h = PLCHealth(host="10.0.0.1", port=502, proto="modbus",
                  reachable=True, state=State.FAULT,
                  faults=[Fault(code="0x04", description="Slave Device Failure",
                                source="modbus")])
    d = h.to_dict()
    assert d["state"] == "FAULT"
    assert d["faults"][0]["code"] == "0x04"
    json.dumps(d)  # must not raise
