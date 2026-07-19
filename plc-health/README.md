# plchealth — live PLC fault/diagnostic reader

Reads the live health of a running PLC over its native protocol and reports
it with a scriptable exit code. Companion to `assetinv` (inventory) and the
ICS YARA scanner (bytes at rest); `plchealth` reads live device state.

## Protocols
- **Modbus TCP** (502) — status register + Modbus exception decode
- **S7comm** (102) — CPU RUN/STOP/DEFECT via SZL 0x0424 + diag buffer SZL 0x00A0
- **EtherNet/IP** (44818) — CIP Identity status word + state byte

## Usage
    cd plc-health
    python3 -m plchealth poll 10.0.0.5                 # auto-detect protocol
    python3 -m plchealth poll 10.0.0.5 --proto s7
    python3 -m plchealth poll 10.0.0.5 --proto modbus --modbus-fault-bit 0
    python3 -m plchealth poll 10.0.0.5 --json health.json

Exit codes: 0 healthy, 1 fault/degraded, 2 unreachable/error.

Read-only — never writes to or controls the PLC.

## Testing
Primary tests run against bundled stdlib mock servers in `../sandbox/`:

    cd plc-health && python3 -m pytest --ignore=tests/sim

Optional cross-checks against real simulators (pymodbus/snap7/cpppo):

    pip install -r requirements-dev.txt
    python3 -m pytest tests/sim -m sim

## Scope
Modbus has no CPU RUN/STOP concept; health there is inferred from
connectivity, Modbus exceptions, and a configurable fault register. S7 and
CIP expose real operating-state/fault fields.
