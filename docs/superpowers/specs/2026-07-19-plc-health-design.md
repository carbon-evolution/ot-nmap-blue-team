# plchealth — Live PLC Fault/Diagnostic Reader — Design Spec

Date: 2026-07-19
Status: Approved by user (new package in ot-nmap-blue-team; Modbus + S7comm +
EtherNet/IP; dual mock + reference-simulator cross-verification)

## Purpose

Read the **live health/fault state** of a running PLC over its native
protocol and report it in a scriptable form. This is the companion to
`assetinv` (which inventories devices) and the YARA scanner (which reads
bytes at rest): `plchealth` reads *live device state* that neither of those
can see.

`plchealth poll <host> --proto {modbus,s7,enip,auto}` connects to a PLC,
reads diagnostic/status data, decodes the fault/health state, and emits a
health record. Exit code: `0` healthy, `1` fault detected, `2`
unreachable/usage error — so it can be cron'd for continuous monitoring.

Read-only. It never writes to the PLC. No start/stop/program control.

## Home & packaging

New stdlib-Python package `plc-health/plchealth/` inside the existing
`ot-nmap-blue-team` repo, a sibling to `asset-inventory/assetinv/`, following
the same structure (small focused modules + `cli.py`/`__main__.py` + a
`tests/` dir + a CI step). Python 3 stdlib only for the reader and the
bundled mocks (`socket`, `struct`, `argparse`, `dataclasses`, `json`,
`csv`). Optional **dev/test-only** deps (`python-snap7`, `pymodbus`,
`cpppo`) live in `plc-health/requirements-dev.txt` and are never required to
build or run the tool. Work merged via PR.

## Architecture

```
plc-health/
  plchealth/
    __init__.py
    __main__.py         # python -m plchealth -> cli.main
    model.py            # PLCHealth, Fault dataclasses; State enum
    faultcodes.py       # decode tables (Modbus exc, S7 CPU state, CIP status)
    probes/
      __init__.py
      base.py           # Probe protocol/ABC: probe(host, port, timeout) -> PLCHealth
      modbus.py         # Modbus TCP status register + exception decode
      s7.py             # S7comm COTP/setup + SZL 0x0424 + SZL 0x00A0 diag buffer
      enip.py           # EtherNet/IP ListIdentity status word + state byte
    poller.py           # protocol selection (incl. auto) -> run probe -> PLCHealth
    cli.py              # `poll` subcommand, JSON/CSV output, exit codes
  tests/
    conftest.py         # mock-server fixtures (spawn/teardown on high ports)
    test_modbus_probe.py
    test_s7_probe.py
    test_enip_probe.py
    test_poller.py
    test_cli.py
    test_faultcodes.py
    sim/                # optional reference-simulator cross-checks (gated)
      test_modbus_sim.py
      test_s7_sim.py
      test_enip_sim.py
  requirements-dev.txt
  README.md
```

### Data model (`model.py`)

- `class State(enum.Enum)`: `RUN, STOP, STARTUP, DEFECT, HOLD, FAULT,
  UNKNOWN, UNREACHABLE`. (`FAULT` = a fault condition without a distinct
  CPU-mode concept, e.g. Modbus/CIP; `DEFECT`/`HOLD` are S7-specific modes.)
- `@dataclass Fault`: `code: str`, `description: str`, `source: str`
  (which decode table), optional `timestamp: str`, `raw: str` (hex).
- `@dataclass PLCHealth`: `host, port, proto, reachable: bool,
  state: State, faults: list[Fault], identity: dict, raw: bytes|None`.
  Method `healthy() -> bool` = reachable and state in {RUN} and no faults.

### Probes (`probes/`)

Each probe is one function/class implementing `base.Probe`:
`probe(host, port, timeout) -> PLCHealth`. Probes only build sockets and
parse bytes; they do not decide exit codes or output.

- **modbus.py** (default port 502): opens Modbus TCP, issues a Read Holding
  Registers (fn 0x03) on a configurable status register (default documented,
  e.g. a health/fault word), and a Read Coils where useful. If the PLC
  replies with an **exception** (function byte | 0x80), decode the exception
  code via `faultcodes.MODBUS_EXCEPTIONS` into a `Fault`. Modbus has no CPU
  RUN/STOP concept: `state = RUN` when it answers cleanly, `FAULT` when a
  fault register bit is set or an exception is returned, `UNREACHABLE` on
  connect failure. Register address/bit is configurable via CLI
  (`--modbus-status-reg`, `--modbus-fault-bit`).
- **s7.py** (default port 102): COTP Connection Request/Confirm, S7comm
  setup-communication, then two SZL reads:
    - **SZL-ID 0x0424** → current CPU operating state, mapped by
      `faultcodes.S7_CPU_STATE` to `RUN/STOP/STARTUP/DEFECT/HOLD`.
    - **SZL-ID 0x00A0** → diagnostic buffer; each entry decoded to a
      `Fault` (event ID + timestamp) via `faultcodes.S7_DIAG_EVENTS`
      (best-effort; unknown event IDs reported by hex code).
- **enip.py** (default port 44818): send CIP encapsulation ListIdentity
  (0x0063), parse the Identity CPF item's `status` uint16 and `state`
  uint8. Decode status-word bits via `faultcodes.CIP_STATUS_BITS`
  (owned, configured, minor recoverable fault, minor unrecoverable fault,
  major recoverable fault, major unrecoverable fault) and the state byte
  (2=faulted, 3=stopped/idle, 4=running, ...). Any major/minor fault bit →
  `state = FAULT` with a `Fault` per set bit.

### Poller (`poller.py`)

- `poll(host, proto, ports, timeout) -> PLCHealth`.
- `proto == "auto"`: TCP-connect-probe 502, 102, 44818 in order; run the
  first protocol whose port is open. If none open → `PLCHealth` with
  `reachable=False, state=UNREACHABLE`.
- Explicit proto: run that probe directly on its port (overridable).

### CLI (`cli.py`)

- `plchealth poll HOST [--proto auto|modbus|s7|enip] [--port N]
  [--timeout S] [--json f] [--csv f] [--modbus-status-reg N]
  [--modbus-fault-bit N]`.
- Prints a one-line human summary (host, proto, state, fault count) plus a
  detail block listing each fault. `--json`/`--csv` write the full record.
- Exit codes: `0` healthy (reachable, RUN, no faults), `1` a fault/degraded
  state detected (reachable but STOP/DEFECT/FAULT/HOLD or faults present),
  `2` unreachable or usage error.

## Error handling

- Connect timeout / refused / reset → `reachable=False, state=UNREACHABLE`,
  exit 2. Never a stack trace.
- Malformed/short protocol response → `state=UNKNOWN` with a `Fault` noting
  the parse failure and the raw hex; exit 1 (degraded, not crash).
- All socket work uses explicit timeouts; no probe can hang the CLI.

## Testing — dual cross-verification

### 1. Bundled mock servers (primary; runs in CI)

Extend the existing `sandbox` mocks so they answer **diagnostic/fault**
queries in addition to identity:
- `s7commplus_mock_server.py` → add SZL 0x0424 (configurable CPU state) and
  SZL 0x00A0 (configurable diag-buffer entries) responses.
- `enip_mock_server.py` → make the Identity `status`/`state` fields
  settable so it can present a faulted device.
- Add `modbus_mock_server.py` → answers Read Holding Registers and can
  return a configurable exception or a fault-bit-set register.

`tests/conftest.py` spawns each mock on a high, unprivileged port
(avoids 102/502/44818 privilege/collision), waits for readiness, and tears
it down. Each `test_*_probe.py` runs the real probe against the mock and
asserts the decoded `PLCHealth` (state + faults). Pure stdlib; always green.

### 2. Reference-simulator cross-check (optional; gated)

The same probe code run against a third-party **full simulator**, asserting
it decodes to the **same** state/fault as the mock — proving the reader is
not overfit to our own mock:
- Modbus → `pymodbus` server (or OpenPLC if running)
- S7comm → `python-snap7` server API
- EtherNet/IP → `cpppo` server

`tests/sim/` cross-checks are guarded: each `skip`s unless its library is
importable (and/or the sim is reachable). CI stays green without them; the
developer runs `pip install -r requirements-dev.txt` and
`pytest plc-health/tests/sim` locally for the deeper validation.

### CI

Add a `plc-health` job/step to the repo CI: `pytest plc-health/tests`
(the bundled-mock suite). The `sim/` directory is excluded from the default
CI run (its deps are not installed there).

## Non-goals (explicit)

- No writes/control (start/stop/program/download) — read-only diagnostics.
- No firmware file analysis — that is the YARA scanner's job (bytes at rest).
- No new protocols beyond Modbus/S7/EtherNet-IP in v1 (DNP3, BACnet, IEC-104
  are candidate follow-ups; the `probes/` interface makes them additive).
- Modbus does not report CPU RUN/STOP; health there is inferred from
  connectivity + exceptions + a configurable fault register, documented as
  such rather than faked.
