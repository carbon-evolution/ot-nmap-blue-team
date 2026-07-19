"""Decode tables mapping raw protocol codes to human-readable fault text."""

# Modbus exception codes (MODBUS Application Protocol v1.1b3, section 7).
MODBUS_EXCEPTIONS = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Slave Device Failure",
    0x05: "Acknowledge",
    0x06: "Slave Device Busy",
    0x08: "Memory Parity Error",
    0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Device Failed To Respond",
}


def modbus_exception_name(code: int) -> str:
    return MODBUS_EXCEPTIONS.get(code, f"Unknown Exception 0x{code:02x}")


# Siemens S7 CPU operating states (SZL 0x0424 mode byte).
S7_CPU_STATE = {
    0x00: "UNKNOWN",
    0x01: "STARTUP",
    0x02: "STARTUP",
    0x03: "STARTUP",
    0x04: "STOP",
    0x05: "HOLD",
    0x08: "RUN",
    0x10: "DEFECT",
}


def s7_cpu_state_name(code: int) -> str:
    name = S7_CPU_STATE.get(code)
    return name if name else f"UNKNOWN(0x{code:02x})"


# CIP Identity object status word bits (Vol.1 5-2.2). Bits 4..7 encode the
# fault severity nibble.
CIP_STATUS_BITS = {
    0: "Owned",
    2: "Configured",
}
_CIP_FAULT_NIBBLE = {
    0b0100: "Minor Recoverable Fault",
    0b0101: "Minor Unrecoverable Fault",
    0b1000: "Major Recoverable Fault",
    0b1001: "Major Unrecoverable Fault",
}


def cip_status_faults(status: int) -> list:
    """Return the fault descriptions encoded in the CIP status word."""
    out = []
    nibble = (status >> 4) & 0x0F
    if nibble in _CIP_FAULT_NIBBLE:
        out.append(_CIP_FAULT_NIBBLE[nibble])
    return out


CIP_STATE = {
    0: "Nonexistent",
    1: "Device Self Testing",
    2: "Faulted",
    3: "Standby",
    4: "Running/Idle",
    5: "Major Recoverable Fault",
}


def cip_state_name(state: int) -> str:
    return CIP_STATE.get(state, f"Unknown({state})")
