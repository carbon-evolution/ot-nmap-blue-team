from plchealth import faultcodes as fc


def test_modbus_exception_lookup():
    assert fc.MODBUS_EXCEPTIONS[0x01] == "Illegal Function"
    assert fc.MODBUS_EXCEPTIONS[0x04] == "Slave Device Failure"
    assert fc.modbus_exception_name(0x06) == "Slave Device Busy"
    assert fc.modbus_exception_name(0x7F) == "Unknown Exception 0x7f"


def test_s7_cpu_state_lookup():
    assert fc.S7_CPU_STATE[0x08] == "RUN"
    assert fc.S7_CPU_STATE[0x04] == "STOP"
    assert fc.s7_cpu_state_name(0x08) == "RUN"
    assert fc.s7_cpu_state_name(0xEE) == "UNKNOWN(0xee)"


def test_cip_status_bits_decode():
    faults = fc.cip_status_faults(0x0040)
    assert "Minor Recoverable Fault" in faults
    assert fc.cip_status_faults(0x0000) == []


def test_cip_state_name():
    assert fc.cip_state_name(2) == "Faulted"
    assert fc.cip_state_name(4) == "Running/Idle"
    assert fc.cip_state_name(99) == "Unknown(99)"
