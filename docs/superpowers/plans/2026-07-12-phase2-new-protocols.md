# Phase 2 (New OT Protocols) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three T1-safe read-only OT discovery scripts — EtherNet/IP CIP, BACnet/IP, S7comm-plus — each with a honeypot-grade mock, a mock-driven pytest test, and CI coverage, plus a UDP scan path in the test harness (which also converts the Phase 1 PROFINET-CM `xfail` into a real passing test).

**Architecture:** Mirror the Phase 1 pattern per protocol: adapt the upstream Redpoint script into `improved-scripts/<proto>-...-improved.nse`, build a standalone honeypot mock in `sandbox/<proto>_mock_server.py` (`--port` + `--profile`), and add `sandbox/tests/test_<proto>.py`. New scripts are written test-first: because we control the NSE output labels, the test defines the contract and the NSE is written to emit exactly those labels (avoiding the Phase 1 "assumed field was wrong" problem). CI needs no workflow change — the `luac -p` gate globs all `.nse` and the pytest jobs already exist.

**Tech Stack:** Lua 5.4 NSE (nmap 7.9x), Python 3 honeypot mocks, pytest, GitHub Actions.

**CRITICAL PORTING NOTE:** All three upstream base scripts (`Redpoint/enip-enumerate.nse`, `Redpoint/BACnet-discover-enumerate.nse`, `Redpoint/s7-enumerate.nse`) use the **removed `bin.pack`/`bin.unpack` API**, which crashes at runtime on nmap 7.9x/Lua 5.4 (the exact bug Phase 1 fixed). Every improved script MUST use `string.pack`/`string.unpack` instead. Remember `bin.unpack` returned `(pos, val)` but `string.unpack` returns `(val, pos)` — argument/return order differs. Verify each new script both `luac -p` passes AND actually runs against its mock (Phase 1 proved these are different guarantees).

---

## File Structure

- `sandbox/tests/conftest.py` — MODIFY: add `udp=False` kwarg to `nmap_scan` (adds `-sU`). Non-breaking.
- `sandbox/tests/test_standard.py` — MODIFY: convert `test_profinet` from `xfail` to a real privileged UDP test.
- `improved-scripts/enip-identity-improved.nse` — CREATE: EtherNet/IP ListIdentity.
- `sandbox/enip_mock_server.py` — CREATE: EtherNet/IP honeypot (TCP 44818).
- `sandbox/tests/test_enip.py` — CREATE.
- `improved-scripts/bacnet-discover-improved.nse` — CREATE: BACnet/IP ReadProperty.
- `sandbox/bacnet_mock_server.py` — CREATE: BACnet honeypot (UDP 47808).
- `sandbox/tests/test_bacnet.py` — CREATE.
- `improved-scripts/s7comm-plus-info-improved.nse` — CREATE: S7comm-plus identity.
- `sandbox/s7commplus_mock_server.py` — CREATE: S7comm-plus honeypot (TCP 102, `--port` configurable).
- `sandbox/tests/test_s7commplus.py` — CREATE.
- `README.md` — MODIFY: catalog + counts (13 → 16 scripts, 6 → 9 standalone mocks).

Work happens on branch `feat/phase2-new-protocols` (already created; the design spec is committed there).

**Mock conventions (match the 6 lesser-known mocks in `sandbox/`):** argparse with `--port` (int, required by the test harness) and `--profile` (choices), a TCP or UDP listener, `SO_REUSEADDR`, prompt responses, and clean shutdown on SIGTERM. Read `sandbox/gesrtp_mock_server.py` for the reference shape (TCP) and the `profinet` handler in `sandbox/ot_mock_servers.py` for a UDP example.

**Harness facts (from Phase 1):** `conftest.py` exposes `mock_server(script, port, *args, inject_port=True)`, `nmap_scan(port, script_path, script_args=None)` → `(fields_dict, raw_stdout)` where `parse_fields` lowercases every `| Label: Value` line, and constants `LESSER`, `SCRIPTS` (=`improved-scripts/`), `SANDBOX`. Privileged tests use `@pytest.mark.privileged` + `@pytest.mark.skipif(os.geteuid() != 0, ...)`.

---

## Task 1: UDP harness path + PROFINET-CM retro-fix

Extend the harness to scan UDP, and use it to turn the Phase 1 PROFINET `xfail` into a real privileged test. This validates the UDP path against an existing mock before BACnet depends on it.

**Files:**
- Modify: `sandbox/tests/conftest.py`
- Modify: `sandbox/tests/test_standard.py`

- [ ] **Step 1: Add the `udp` kwarg to `nmap_scan`**

In `sandbox/tests/conftest.py`, replace the `nmap_scan` function with:
```python
def nmap_scan(port, script_path, script_args=None, udp=False):
    """Run nmap against 127.0.0.1:port with one NSE script.

    udp=True issues a UDP scan (nmap -sU), which requires root. Returns
    (fields_dict, raw_stdout).
    """
    proto_flag = "-sU" if udp else "-sT"
    cmd = ["nmap", "-Pn", proto_flag, "-p", str(port),
           "--script", script_path, "127.0.0.1"]
    if script_args:
        cmd += ["--script-args", script_args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = proc.stdout
    if proc.returncode != 0:
        out += f"\n[nmap exited {proc.returncode}]\n{proc.stderr}"
    return parse_fields(out), out
```
Note: the timeout is raised to 120s because `-sU` is slower. `-sT` (connect scan) is the explicit default for the TCP path — behaviourally identical to the prior bare `-p` for the unprivileged tests.

- [ ] **Step 2: Convert `test_profinet` to a real UDP privileged test**

In `sandbox/tests/test_standard.py`, replace the existing `test_profinet` (currently `@pytest.mark.xfail(... UDP ...)`) with:
```python
@pytest.mark.privileged
@pytest.mark.skipif(os.geteuid() != 0, reason="UDP scan (-sU) needs root")
def test_profinet(mock_server):
    # PROFINET-CM is UDP 34964; the all-in-one mock serves it. Uses the UDP
    # harness path (nmap -sU), which requires root.
    mock_server(MOCK, 34964, "--profinet", inject_port=False)
    fields, out = nmap_scan(34964, _script("profinet-cm-lookup-improved.nse"), udp=True)
    assert "devicename" in fields or "device name" in fields or "vendor" in fields, out
```
The exact asserted label must match what `profinet-cm-lookup-improved.nse` actually prints. During implementation, run this as root (or read the NSE's output builder) and reconcile the assertion to the real lowercased label(s); keep it a real assertion, not `assert out`.

- [ ] **Step 3: Verify no regression + collection**

Run: `cd sandbox/tests && python3 -m pytest -m "not privileged" -q`
Expected: `12 passed, ... xfailed` — the same as Phase 1 minus the profinet xfail (now deselected as privileged). No errors. `test_profinet` shows as deselected (privileged), not xfailed.
Run: `python3 -m pytest test_standard.py --collect-only -q` → all 7 standard test functions still collected.
If you have root: `sudo python3 -m pytest test_standard.py::test_profinet -v` → PASS. If not, note it runs first under CI-root.

- [ ] **Step 4: Commit**

```bash
git add sandbox/tests/conftest.py sandbox/tests/test_standard.py
git commit -m "test(harness): add UDP scan path; make PROFINET-CM a real privileged test

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: EtherNet/IP CIP (mock + improved NSE + test)

The unprivileged, live-verifiable protocol — establishes the new-protocol pattern end-to-end. TCP 44818, `ListIdentity` (encapsulation command 0x0063). Read-only.

**Files:**
- Create: `sandbox/enip_mock_server.py`
- Create: `improved-scripts/enip-identity-improved.nse`
- Create: `sandbox/tests/test_enip.py`

**Protocol reference (EtherNet/IP encapsulation):** A ListIdentity request is a 24-byte encapsulation header with command `0x0063`, length `0`, session `0`, status `0`, sender-context 8 bytes, options `0`. The response is the same header (with a length) followed by an item count (uint16) and one CPF item: item type `0x000C`, item length, then the Identity body: `protocol_version` (uint16), `socket_address` (16 bytes: sin_family/port/addr/zero), `vendor_id` (uint16), `device_type` (uint16), `product_code` (uint16), `revision` (2 bytes major.minor), `status` (uint16), `serial_number` (uint32), `product_name_len` (uint8) + product_name (ASCII), `state` (uint8). All multi-byte encapsulation fields are little-endian. Adapt `Redpoint/enip-enumerate.nse` for the parser but port `bin.unpack` → `string.unpack`.

**NSE output contract (the improved script MUST emit these exact labels):** `Vendor`, `Product Name`, `Serial Number`, `Device Type`, `Product Code`, `Revision`, `Device State`. (After `parse_fields` lowercasing: `vendor`, `product name`, `serial number`, `device type`, `product code`, `revision`, `device state`.)

**Mock profiles (each varies vendor/product code/serial/product name):**
- `controllogix`: vendor_id 1 → "Rockwell Automation/Allen-Bradley", device_type 14 → "Programmable Logic Controller", product_code 54, revision 20.11, serial 0x00C0FFEE, product_name "1756-L61/B LOGIX5561", state 3.
- `micro850`: vendor_id 1, device_type 14, product_code 140, revision 12.11, serial 0x00D1E5EE, product_name "2080-LC50-24QWB", state 3.
- `omron_nx`: vendor_id 47 → "OMRON Corporation", device_type 14, product_code 9000, revision 1.13, serial 0x00AB1201, product_name "NX102-9000", state 3.

- [ ] **Step 1: Write the failing test**

`sandbox/tests/test_enip.py`:
```python
import os
from conftest import SCRIPTS, nmap_scan

SCRIPT = os.path.join(SCRIPTS, "enip-identity-improved.nse")


def test_enip_extracts_identity(mock_server):
    mock_server("enip_mock_server.py", 44818, "--profile", "controllogix")
    fields, out = nmap_scan(44818, SCRIPT)
    assert "product name" in fields, out
    assert "1756-L61" in fields["product name"], out
    assert "serial number" in fields, out
    assert "vendor" in fields, out
    assert "Allen-Bradley" in fields["vendor"], out


def test_enip_profiles_differ(mock_server):
    m = mock_server("enip_mock_server.py", 44818, "--profile", "controllogix")
    a, _ = nmap_scan(44818, SCRIPT)
    m.stop()
    mock_server("enip_mock_server.py", 44818, "--profile", "omron_nx")
    b, _ = nmap_scan(44818, SCRIPT)
    assert a.get("product name") != b.get("product name"), (a, b)
```

- [ ] **Step 2: Run to confirm it FAILS**

Run: `cd sandbox/tests && python3 -m pytest test_enip.py -v`
Expected: FAIL — mock/script don't exist yet (`nmap` finds no open port / no script output).

- [ ] **Step 3: Implement the mock `sandbox/enip_mock_server.py`**

Build a TCP honeypot on `--port` (default 44818) matching the `sandbox/gesrtp_mock_server.py` conventions (argparse `--port`/`--profile {controllogix,micro850,omron_nx}`, `SO_REUSEADDR`, per-connection handler, detection logging, small scan-delay jitter, clean SIGTERM). On receiving an encapsulation request with command `0x0063` (ListIdentity), reply with a valid ListIdentity response whose Identity body is built from the selected profile's fields (structure above, little-endian). Ignore/echo other commands harmlessly. Use a `PROFILES` dict keyed by the three profile names, each holding vendor_id, vendor_name, device_type, product_code, revision (major,minor), serial, product_name, state.

- [ ] **Step 4: Implement the improved NSE `improved-scripts/enip-identity-improved.nse`**

Adapt `Redpoint/enip-enumerate.nse` down to the read-only ListIdentity path: `portrule = shortport.port_or_service(44818, "EtherNet/IP-2", "tcp")`; send the 24-byte ListIdentity request; parse the response with `string.unpack` (little-endian format string, e.g. `"<I2"` for uint16, `"<I4"` for uint32, `"I1"` for uint8, and a length-prefixed string for product name); map vendor_id/device_type to human names via small lookup tables (keep the upstream tables, trimmed); emit the seven output labels above via `stdnse.output_table()` or an ordered table. Keep it T1-safe: ListIdentity only, no CIP object reads, no writes. Guard the parse with `pcall` (Phase 1 lesson).

- [ ] **Step 5: Syntax-check then run the test**

Run: `luac -p improved-scripts/enip-identity-improved.nse && cd sandbox/tests && python3 -m pytest test_enip.py -v`
Expected: both tests PASS. `product name` contains "1756-L61", `vendor` contains "Allen-Bradley", profiles differ.

- [ ] **Step 6: Commit**

```bash
git add improved-scripts/enip-identity-improved.nse sandbox/enip_mock_server.py sandbox/tests/test_enip.py
git commit -m "feat(enip): EtherNet/IP ListIdentity script + honeypot mock + test

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: BACnet/IP (mock + improved NSE + test)

UDP 47808, ReadProperty on the Device object. Uses the Task 1 UDP harness path → **privileged** test.

**Files:**
- Create: `sandbox/bacnet_mock_server.py`
- Create: `improved-scripts/bacnet-discover-improved.nse`
- Create: `sandbox/tests/test_bacnet.py`

**Protocol reference (BACnet/IP):** BVLC header (`0x81` type, function `0x0A` Original-Unicast-NPDU, length uint16) + NPDU (version `0x01`, control) + APDU. Discovery = Confirmed-Request ReadProperty (or a series) for the Device object (object-type 8) reading properties: object-name (77), vendor-name (121), vendor-identifier (120), model-name (70), firmware-revision (44), application-software-version (12), location (58), description (28). The mock may answer a single ReadPropertyMultiple, or answer individual ReadProperty requests. All BACnet integers are big-endian; property values are ASCII character strings (tag 7) prefixed by a length. Adapt `Redpoint/BACnet-discover-enumerate.nse` for request construction and response parsing; port `bin.unpack` → `string.unpack`.

**NSE output contract (exact labels):** `Vendor`, `Model Name`, `Firmware`, `Application Software`, `Object Name`, `Location`, `Description`. (Lowercased: `vendor`, `model name`, `firmware`, `application software`, `object name`, `location`, `description`.)

**Mock profiles (vary vendor/model/firmware/object-name):**
- `automated_logic`: vendor-id 24 → "Automated Logic Corporation", model-name "LGR1000", firmware "6.02", app-software "OS-6.02b", object-name "ALC-VAV-101", location "Bldg-A/Fl-3", description "VAV Controller".
- `siemens_bas`: vendor-id 7 → "Siemens Industry, Inc.", model-name "PXC00-E.D", firmware "3.5.1", app-software "APOGEE-3.5", object-name "SBT-AHU-02", location "Bldg-B/Roof", description "AHU Controller".
- `honeywell_bas`: vendor-id 17 → "Honeywell Inc.", model-name "CIPer 50", firmware "9.0.1", app-software "Niagara-4.9", object-name "HON-JACE-07", location "Bldg-C/Fl-1", description "Supervisory Controller".

- [ ] **Step 1: Write the failing test**

`sandbox/tests/test_bacnet.py`:
```python
import os
import pytest
from conftest import SCRIPTS, nmap_scan

SCRIPT = os.path.join(SCRIPTS, "bacnet-discover-improved.nse")

pytestmark = pytest.mark.privileged
not_root = os.geteuid() != 0
skip_reason = "UDP scan (-sU) needs root"


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_bacnet_extracts_device(mock_server):
    mock_server("bacnet_mock_server.py", 47808, "--profile", "automated_logic")
    fields, out = nmap_scan(47808, SCRIPT, udp=True)
    assert "vendor" in fields, out
    assert "Automated Logic" in fields["vendor"], out
    assert "model name" in fields, out
    assert fields["model name"] == "LGR1000", out


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_bacnet_profiles_differ(mock_server):
    m = mock_server("bacnet_mock_server.py", 47808, "--profile", "automated_logic")
    a, _ = nmap_scan(47808, SCRIPT, udp=True)
    m.stop()
    mock_server("bacnet_mock_server.py", 47808, "--profile", "siemens_bas")
    b, _ = nmap_scan(47808, SCRIPT, udp=True)
    assert a.get("model name") != b.get("model name"), (a, b)
```

- [ ] **Step 2: Run to confirm it SKIPS (non-root) / FAILS (root)**

Run: `cd sandbox/tests && python3 -m pytest test_bacnet.py -v`
Expected non-root: 2 SKIPPED. Expected as root before implementation: FAIL (no mock/script). Confirm no import/collection error.

- [ ] **Step 3: Implement the mock `sandbox/bacnet_mock_server.py`**

Build a **UDP** honeypot on `--port` (default 47808) matching mock conventions (argparse `--port`/`--profile {automated_logic,siemens_bas,honeywell_bas}`, `SO_REUSEADDR`, `recvfrom`/`sendto` loop, detection logging, clean SIGTERM). On receiving a ReadProperty / ReadPropertyMultiple for the Device object, respond with a BVLC+NPDU+APDU ComplexACK carrying the selected profile's property values (character-string tags). A `PROFILES` dict holds the eight properties per profile. Bind UDP and reply to the sender's address.

- [ ] **Step 4: Implement the improved NSE `improved-scripts/bacnet-discover-improved.nse`**

Adapt `Redpoint/BACnet-discover-enumerate.nse` to the read-only property set above: `portrule = shortport.port_or_service(47808, "bacnet", "udp")`; send the ReadProperty request(s); parse the ComplexACK character-string values with `string.unpack`; emit the seven labels above. Keep T1-safe (read the standard identity properties only; no writes, no object enumeration beyond the Device object). `pcall`-guard the parse.

- [ ] **Step 5: Syntax-check; run as root**

Run: `luac -p improved-scripts/bacnet-discover-improved.nse`
Then, as root (or note it defers to CI-root): `sudo python3 -m pytest test_bacnet.py -v`
Expected: both PASS — `vendor` contains "Automated Logic", `model name` == "LGR1000", profiles differ. If you cannot run as root locally, reconcile the asserted labels/values by reading the mock + NSE (as Phase 1 did for Red Lion/Modbus) and state that CI-root is the first real run.

- [ ] **Step 6: Commit**

```bash
git add improved-scripts/bacnet-discover-improved.nse sandbox/bacnet_mock_server.py sandbox/tests/test_bacnet.py
git commit -m "feat(bacnet): BACnet/IP ReadProperty script + UDP honeypot mock + test

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: S7comm-plus (mock + improved NSE + test) — highest risk

TCP 102 (COTP/ISO-TSAP), **privileged**. The mock takes a configurable `--port` (default 102). See the FIDELITY FALLBACK below before implementing.

**Files:**
- Create: `sandbox/s7commplus_mock_server.py`
- Create: `improved-scripts/s7comm-plus-info-improved.nse`
- Create: `sandbox/tests/test_s7commplus.py`

**Protocol reference:** TPKT (`0x03 0x00` + length uint16) wraps COTP. First a COTP Connection Request (CR) → Connection Confirm (CC). Then, for classic-S7-style identification that S7-1200/1500 still commonly answer, an S7comm ROSCTR=Userdata SZL read of SZL-ID `0x001C` (component identification) and `0x0011` (module identification) returns: System Name, Module Type, Module (order/MLFB), Serial Number, Basic Hardware, Version. S7comm-plus (S7-1200/1500) additionally uses a session-based handshake on top of COTP; the improved script attempts the SZL identity first and, where the device is S7comm-plus-only, falls back to fingerprinting the S7comm-plus initial response. Adapt `Redpoint/s7-enumerate.nse` (SZL parsing at fixed offsets) and `ICS-Discovery-Tools/s71200-enumerate-old.nse`; port all `bin.unpack("z", ...)` to `string.unpack("z", ...)` (mind the `(val,pos)` return order).

**NSE output contract (exact labels):** `Module Type`, `Module`, `Version`, `Serial Number`, `System Name`. (Lowercased: `module type`, `module`, `version`, `serial number`, `system name`.)

**Mock profiles (vary order number/firmware/serial/system name):**
- `s7_1200`: system_name "PLC_1200", module_type "CPU 1212C DC/DC/DC", module "6ES7 212-1AE40-0XB0", serial "S C-K1U450132020", basic_hardware "6ES7 212-1AE40-0XB0", version "4.4.0".
- `s7_1500`: system_name "PLC_1500", module_type "CPU 1515-2 PN", module "6ES7 515-2AM01-0AB0", serial "S C-L2X920551024", basic_hardware "6ES7 515-2AM01-0AB0", version "2.9.2".

**FIDELITY FALLBACK (from the approved spec — follow, do not fake):** If a faithful full S7comm-plus session identity read proves intractable to emulate + parse in the mock, scope the mock + NSE down to the COTP-connect + SZL identification exchange that S7-1200/1500 answer (the labels above are all obtainable from SZL 0x1C/0x11). If even the SZL path can't be driven faithfully, mark the test `@pytest.mark.xfail(reason="<specific reason>", strict=False)` — still ship the script, mock, and test function, with the limit documented in the NSE header. Never weaken an assertion to force a pass.

- [ ] **Step 1: Write the failing test**

`sandbox/tests/test_s7commplus.py`:
```python
import os
import pytest
from conftest import SCRIPTS, nmap_scan

SCRIPT = os.path.join(SCRIPTS, "s7comm-plus-info-improved.nse")

pytestmark = pytest.mark.privileged
not_root = os.geteuid() != 0
skip_reason = "port 102 (<1024) needs root"


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_s7commplus_extracts_module(mock_server):
    mock_server("s7commplus_mock_server.py", 102, "--profile", "s7_1200")
    fields, out = nmap_scan(102, SCRIPT)
    assert "module" in fields, out
    assert "6ES7 212" in fields["module"], out
    assert "version" in fields, out
    assert fields["version"] == "4.4.0", out


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_s7commplus_profiles_differ(mock_server):
    m = mock_server("s7commplus_mock_server.py", 102, "--profile", "s7_1200")
    a, _ = nmap_scan(102, SCRIPT)
    m.stop()
    mock_server("s7commplus_mock_server.py", 102, "--profile", "s7_1500")
    b, _ = nmap_scan(102, SCRIPT)
    assert a.get("module") != b.get("module"), (a, b)
```

- [ ] **Step 2: Run to confirm it SKIPS (non-root) / FAILS (root)**

Run: `cd sandbox/tests && python3 -m pytest test_s7commplus.py -v`
Expected non-root: 2 SKIPPED. As root pre-implementation: FAIL. No collection errors.

- [ ] **Step 3: Implement the mock `sandbox/s7commplus_mock_server.py`**

Build a TCP honeypot on `--port` (default 102) matching mock conventions (argparse `--port`/`--profile {s7_1200,s7_1500}`, `SO_REUSEADDR`, detection logging, SIGTERM). Handle: TPKT/COTP CR → CC; then an S7comm Userdata SZL request → SZL response encoding the selected profile's identity at the offsets the NSE parses (System Name, Module Type, Module, Serial Number, Basic Hardware, Version). A `PROFILES` dict holds the six fields per profile. If implementing full S7comm-plus session framing is impractical, implement the SZL identification path per the FALLBACK.

- [ ] **Step 4: Implement the improved NSE `improved-scripts/s7comm-plus-info-improved.nse`**

Adapt `Redpoint/s7-enumerate.nse`: `portrule = shortport.port_or_service(102, "iso-tsap", "tcp")`; perform COTP CR/CC; send the SZL 0x1C/0x11 Userdata reads; parse fixed-offset null-terminated strings with `string.unpack("z", response, <offset>)` (NOT `bin.unpack`); emit the five labels above. Document in the header that this targets S7-1200/1500 (S7comm-plus era) identity via SZL, with the fingerprint fallback. `pcall`-guard parsing.

- [ ] **Step 5: Syntax-check; run as root**

Run: `luac -p improved-scripts/s7comm-plus-info-improved.nse`
Then as root (or defer to CI-root): `sudo python3 -m pytest test_s7commplus.py -v`
Expected: both PASS — `module` contains "6ES7 212", `version` == "4.4.0", profiles differ. If the FALLBACK's xfail path was taken, expected: 2 xfailed with the documented reason (still no errors). Reconcile labels/values by code-reading if not run locally.

- [ ] **Step 6: Commit**

```bash
git add improved-scripts/s7comm-plus-info-improved.nse sandbox/s7commplus_mock_server.py sandbox/tests/test_s7commplus.py
git commit -m "feat(s7comm-plus): S7-1200/1500 identity script + honeypot mock + test

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Docs + finish the branch

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the script catalog and counts**

In `README.md`: add EtherNet/IP CIP (44818/tcp), BACnet/IP (47808/udp), and S7comm-plus (102/tcp) to the "Standard OT Protocols" catalog table and the "What Information Can These Scripts Extract?" table with their real emitted fields. Update the script count from 13 to **16** and the standalone-mock count from 6 to **9** everywhere they appear (badges, intro line, mock-server reference table). Add the three new mocks to the Mock Server Reference table with their ports and profiles. Note in the CI/Testing section that PROFINET-CM is now a real privileged test (no longer xfail).

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add EtherNet/IP, BACnet, S7comm-plus to catalog (13->16 scripts)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 3: Full local verification**

Run: `cd sandbox/tests && python3 -m pytest -m "not privileged" -v`
Expected: all unprivileged tests PASS (now includes EtherNet/IP) or declared xfail; no failures.
Run: `for f in improved-scripts/*.nse improved-scripts/lesser-known/*.nse; do luac -p "$f" || echo "SYNTAX FAIL: $f"; done`
Expected: no syntax failures across all 16 scripts.

- [ ] **Step 4: Push and confirm CI green**

```bash
git push -u origin feat/phase2-new-protocols
gh run list --branch feat/phase2-new-protocols --limit 1
```
Watch the run (`gh run watch <id> --exit-status`). CI runs the luac gate (16 scripts), unprivileged pytest (incl. EtherNet/IP), and privileged pytest as root (BACnet UDP, S7comm-plus 102, PROFINET UDP, plus Phase 1 Red Lion/Modbus/MMS). Expected: green. If a privileged test fails on its first real root run, debug the script/mock (do not weaken the assertion) — this is the Phase 1 modbus lesson.

- [ ] **Step 5: Finish the branch**

Invoke the `superpowers:finishing-a-development-branch` skill to choose merge / PR / keep. (Base branch: `main`.)

---

## Self-Review Notes

- **Spec coverage:** EtherNet/IP (Task 2), BACnet + UDP path (Tasks 1 & 3), S7comm-plus + fallback (Task 4), PROFINET retro-fix (Task 1), harness UDP extension (Task 1), docs/counts (Task 5), CI (Task 5 Step 4 — no workflow change needed, existing jobs cover new files). All spec sections mapped.
- **Naming consistency:** script files `<proto>-...-improved.nse`, mocks `<proto>_mock_server.py`, tests `test_<proto>.py`; output labels defined per protocol and asserted verbatim (lowercased) in each test. `nmap_scan(..., udp=True)` used identically in Tasks 1 & 3.
- **Known real-bug gates:** privileged tests (BACnet, S7comm-plus, PROFINET) first execute under CI-root; profile-difference assertions and the S7comm-plus fallback are allowed to fail loudly — fix the code, never weaken the assertion.
- **Porting gate:** every new script must pass BOTH `luac -p` AND a live run (the Phase 1 `bin`/`bit32` lesson); use `string.pack`/`string.unpack`, not the removed `bin` API.
