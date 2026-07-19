import threading
import time

import pytest

pymodbus = pytest.importorskip("pymodbus")
from pymodbus.server import StartTcpServer  # noqa: E402
from pymodbus.datastore import (  # noqa: E402
    ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext)

from plchealth.probes import modbus  # noqa: E402
from plchealth.model import State  # noqa: E402

pytestmark = pytest.mark.sim


def _serve(port, holding_values):
    store = ModbusSlaveContext(
        hr=ModbusSequentialDataBlock(0, holding_values))
    context = ModbusServerContext(slaves=store, single=True)
    t = threading.Thread(
        target=StartTcpServer,
        kwargs={"context": context, "address": ("127.0.0.1", port)},
        daemon=True)
    t.start()
    time.sleep(0.7)
    return t


def test_probe_reads_pymodbus_register():
    _serve(15099, [0] * 10)
    h = modbus.probe("127.0.0.1", 15099, timeout=2.0)
    assert h.reachable and h.state is State.RUN


def test_probe_detects_fault_bit_on_pymodbus():
    _serve(15098, [1] + [0] * 9)  # register 0 = 1 -> bit0 set
    h = modbus.probe("127.0.0.1", 15098, timeout=2.0,
                     status_reg=0, fault_bit=0)
    assert h.state is State.FAULT
