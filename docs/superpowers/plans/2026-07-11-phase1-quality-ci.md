# Phase 1 (Quality Gaps + Mock-Driven CI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pytest harness that boots each mock server and asserts the matching NSE script extracts the right fields, fix the FF HSE named-field gap, verify Red Lion end-to-end, and enforce it all in GitHub Actions CI.

**Architecture:** A `sandbox/tests/` pytest suite with a shared `conftest.py` (a `mock_server` fixture that launches a mock subprocess and waits for its port, plus an `nmap_scan` helper that runs nmap and parses the `| script:` output block into a dict). One test module per NSE script asserts documented fields are present; profile-capable scripts also assert two profiles differ. Red Lion's test is marked `privileged` (binds TCP 789, needs root). A GitHub Actions workflow installs nmap + luac, runs a syntax gate, then the suite.

**Tech Stack:** Python 3 + pytest, nmap (NSE), luac (Lua 5.4 syntax check), GitHub Actions (ubuntu-latest).

---

## File Structure

- `sandbox/tests/conftest.py` — shared fixtures: `mock_server` factory + `nmap_scan()` + `parse_fields()`. Single responsibility: harness plumbing.
- `sandbox/tests/pytest.ini` — registers the `privileged` marker, sets `testpaths`.
- `sandbox/tests/requirements.txt` — `pytest`.
- `sandbox/tests/test_gesrtp.py`, `test_opcua.py`, `test_melsecq.py`, `test_proconos.py`, `test_ffhse.py`, `test_redlion.py` — one per lesser-known script.
- `sandbox/tests/test_standard.py` — the 7 standard scripts against `ot_mock_servers.py`.
- `improved-scripts/lesser-known/ff-hse-discover-improved.nse` — add banner-label parsing (the fix).
- `.github/workflows/ci.yml` — CI.
- `README.md` — add a "Testing / CI" section.

Work happens on branch `feat/phase1-quality-ci` (already created; the design spec is committed there).

---

## Task 1: Harness scaffolding + one known-good test (GE SRTP)

**Files:**
- Create: `sandbox/tests/requirements.txt`
- Create: `sandbox/tests/pytest.ini`
- Create: `sandbox/tests/conftest.py`
- Create: `sandbox/tests/test_gesrtp.py`

- [ ] **Step 1: Create requirements + pytest.ini**

`sandbox/tests/requirements.txt`:
```
pytest>=8.0
```

`sandbox/tests/pytest.ini`:
```ini
[pytest]
testpaths = .
markers =
    privileged: test needs root (binds a TCP port < 1024)
```

- [ ] **Step 2: Write `conftest.py`**

`sandbox/tests/conftest.py`:
```python
import os
import re
import socket
import subprocess
import sys
import time

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS_DIR))
SANDBOX = os.path.join(REPO, "sandbox")
SCRIPTS = os.path.join(REPO, "improved-scripts")
LESSER = os.path.join(SCRIPTS, "lesser-known")


def _wait_port(port, host="127.0.0.1", timeout=10.0):
    """Poll-connect until the port accepts a TCP connection or timeout."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


class _Mock:
    def __init__(self, script, port, *args):
        self.script = script
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(SANDBOX, script),
             "--port", str(port), *args],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not _wait_port(port):
            self.stop()
            raise RuntimeError(f"{script} never opened port {port}")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def mock_server():
    """Factory fixture: mock_server(script, port, *args) -> running mock.

    All started mocks are torn down at test teardown, even on failure.
    """
    started = []

    def _start(script, port, *args):
        m = _Mock(script, port, *args)
        started.append(m)
        return m

    yield _start
    for m in started:
        m.stop()


def parse_fields(out):
    """Flatten an nmap NSE output block into {lowercased label: value}.

    Grabs any '| ... Label: Value' line (handles '|', '|_', nested indent).
    Header lines like '| script-name:' have no value and are skipped.
    """
    fields = {}
    for line in out.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        content = line.lstrip()[1:].lstrip("_").strip()
        m = re.match(r"^(.+?):\s+(.+)$", content)
        if m:
            fields[m.group(1).strip().lower()] = m.group(2).strip()
    return fields


def nmap_scan(port, script_path, script_args=None):
    """Run nmap against 127.0.0.1:port with one NSE script.

    Returns (fields_dict, raw_stdout).
    """
    cmd = ["nmap", "-Pn", "-p", str(port), "--script", script_path, "127.0.0.1"]
    if script_args:
        cmd += ["--script-args", script_args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    return parse_fields(proc.stdout), proc.stdout
```

- [ ] **Step 3: Write the GE SRTP test (known-good, validates the harness)**

`sandbox/tests/test_gesrtp.py`:
```python
import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "gesrtp-info-improved.nse")


def test_gesrtp_extracts_plc_fields(mock_server):
    mock_server("gesrtp_mock_server.py", 18245, "--profile", "rx3i")
    fields, out = nmap_scan(18245, SCRIPT)
    assert "plc model" in fields, out
    assert "GE PACSystems RX3i" in fields["plc model"]
    assert "firmware version" in fields, out
    assert fields["firmware version"] == "V9.50"


def test_gesrtp_profiles_differ(mock_server):
    # The GE SRTP portrule is pinned to 18245, so profiles can't run
    # simultaneously on different ports. Start profile A, scan, stop it,
    # then start profile B on the same port and scan again.
    m1 = mock_server("gesrtp_mock_server.py", 18245, "--profile", "rx3i")
    a, _ = nmap_scan(18245, SCRIPT)
    m1.stop()
    mock_server("gesrtp_mock_server.py", 18245, "--profile", "ge90_30")
    b, _ = nmap_scan(18245, SCRIPT)
    assert a.get("cpu type") != b.get("cpu type"), (a, b)
```

- [ ] **Step 4: Run and verify**

Run: `cd sandbox/tests && python3 -m pytest test_gesrtp.py -v`
Expected: both tests PASS (GE SRTP is known-good; verified end-to-end earlier).
If the profile-difference test fails because both profiles yield the same CPU type, that is a real profile-fidelity bug for GE SRTP — record it and fix in Task 5's sweep, do not weaken the assertion.

- [ ] **Step 5: Commit**

```bash
git add sandbox/tests/requirements.txt sandbox/tests/pytest.ini sandbox/tests/conftest.py sandbox/tests/test_gesrtp.py
git commit -m "test: pytest harness + GE SRTP mock-driven test"
```

---

## Task 2: Tests for OPC UA, MELSEC-Q, ProConOS

**Files:**
- Create: `sandbox/tests/test_opcua.py`
- Create: `sandbox/tests/test_melsecq.py`
- Create: `sandbox/tests/test_proconos.py`

Expected fields come from the README catalog. Ports/profiles (from mock `--help`):
opcua 4840 `--profile {generic,siemens_s7,rockwell_logix}`;
melsecq 5007 `--profile {q03udvcpu,q06udvcpu,q13udvcpu,q26udvcpu}`;
proconos 20547 `--profile {adam5510e,adam5510kw,adam5510m,generic}`.

- [ ] **Step 1: Write `test_opcua.py`**

```python
import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "opcua-discovery-improved.nse")


def test_opcua_extracts_application_fields(mock_server):
    mock_server("opcua_mock_server.py", 4840, "--profile", "siemens_s7")
    fields, out = nmap_scan(4840, SCRIPT)
    assert "application name" in fields, out
    assert "application uri" in fields, out


def test_opcua_profiles_differ(mock_server):
    m = mock_server("opcua_mock_server.py", 4840, "--profile", "siemens_s7")
    a, _ = nmap_scan(4840, SCRIPT)
    m.stop()
    mock_server("opcua_mock_server.py", 4840, "--profile", "rockwell_logix")
    b, _ = nmap_scan(4840, SCRIPT)
    assert a.get("application uri") != b.get("application uri"), (a, b)
```

- [ ] **Step 2: Write `test_melsecq.py`**

```python
import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "melsecq-info-improved.nse")


def test_melsecq_extracts_plc_type(mock_server):
    mock_server("melsecq_mock_server.py", 5007, "--profile", "q03udvcpu")
    fields, out = nmap_scan(5007, SCRIPT)
    assert "plc type" in fields, out
    assert fields["plc type"].startswith("Q03")


def test_melsecq_profiles_differ(mock_server):
    m = mock_server("melsecq_mock_server.py", 5007, "--profile", "q03udvcpu")
    a, _ = nmap_scan(5007, SCRIPT)
    m.stop()
    mock_server("melsecq_mock_server.py", 5007, "--profile", "q26udvcpu")
    b, _ = nmap_scan(5007, SCRIPT)
    assert a.get("plc type") != b.get("plc type"), (a, b)
```

- [ ] **Step 3: Write `test_proconos.py`**

```python
import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "proconos-info-improved.nse")


def test_proconos_extracts_runtime(mock_server):
    mock_server("proconos_mock_server.py", 20547, "--profile", "adam5510kw")
    fields, out = nmap_scan(20547, SCRIPT)
    assert "runtime" in fields, out


def test_proconos_profiles_differ(mock_server):
    m = mock_server("proconos_mock_server.py", 20547, "--profile", "adam5510kw")
    a, _ = nmap_scan(20547, SCRIPT)
    m.stop()
    mock_server("proconos_mock_server.py", 20547, "--profile", "adam5510e")
    b, _ = nmap_scan(20547, SCRIPT)
    assert a.get("plc model") != b.get("plc model"), (a, b)
```

- [ ] **Step 4: Run and verify**

Run: `cd sandbox/tests && python3 -m pytest test_opcua.py test_melsecq.py test_proconos.py -v`
Expected: field-presence tests PASS. If any `*_profiles_differ` fails because the mock ignores its profile for that field, that is a real bug — leave the test failing/xfail-marked with a `reason` and fix it in Task 5. Do not delete the assertion.

- [ ] **Step 5: Commit**

```bash
git add sandbox/tests/test_opcua.py sandbox/tests/test_melsecq.py sandbox/tests/test_proconos.py
git commit -m "test: OPC UA, MELSEC-Q, ProConOS mock-driven tests"
```

---

## Task 3: FF HSE — failing test, then the named-field fix

The FF HSE mock already sends a per-profile ASCII banner with all fields as
`Label: Value` lines (see `build_banner` in `ffhse_mock_server.py`). The NSE
receives it but does not map labels to names, falling back to `field_1/field_2`.
Fix: add banner-label parsing to the NSE.

**Files:**
- Create: `sandbox/tests/test_ffhse.py`
- Modify: `improved-scripts/lesser-known/ff-hse-discover-improved.nse`

- [ ] **Step 1: Write the failing test**

`sandbox/tests/test_ffhse.py`:
```python
import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "ff-hse-discover-improved.nse")


def test_ffhse_extracts_named_fields(mock_server):
    mock_server("ffhse_mock_server.py", 1089, "--profile", "flow")
    fields, out = nmap_scan(1089, SCRIPT)
    # Named fields, not generic field_1/field_2
    assert "field_1" not in fields, out
    assert "device name" in fields, out
    assert "vendor" in fields, out
    assert "device tag" in fields, out
    assert "hse version" in fields, out
    assert "software revision" in fields, out
    assert "stack" in fields, out
    assert "mac" in fields, out
    # Values come from the 'flow' profile
    assert fields["vendor"] == "Micro Motion"
    assert fields["device tag"] == "FIC-301"


def test_ffhse_profiles_differ(mock_server):
    m = mock_server("ffhse_mock_server.py", 1089, "--profile", "flow")
    a, _ = nmap_scan(1089, SCRIPT)
    m.stop()
    mock_server("ffhse_mock_server.py", 1089, "--profile", "pressure")
    b, _ = nmap_scan(1089, SCRIPT)
    assert a.get("vendor") != b.get("vendor"), (a, b)
```

- [ ] **Step 2: Run to confirm it FAILS**

Run: `cd sandbox/tests && python3 -m pytest test_ffhse.py -v`
Expected: FAIL — `device name` absent, `field_1` present (current fallback behavior).

- [ ] **Step 3: Add banner-label parsing to the NSE**

In `improved-scripts/lesser-known/ff-hse-discover-improved.nse`, add this function
just above `summarize_device_info` (near line 314):
```lua
-- Map raw FF HSE banner labels to canonical output field names.
local BANNER_LABEL_MAP = {
  ["ff_hse device"]     = "Device Name",
  ["device id"]         = "Device Name",
  ["vendor"]            = "Vendor",
  ["vendor name"]       = "Vendor",
  ["device tag"]        = "Device Tag",
  ["device type"]       = "Device Type",
  ["hse version"]       = "HSE Version",
  ["software rev"]      = "Software Revision",
  ["software revision"] = "Software Revision",
  ["stack"]             = "Stack",
  ["mac"]               = "MAC",
}

--- Parse "Label: Value" lines out of an ASCII banner into named fields.
-- @param data string: raw banner bytes
-- @return table: canonical field name -> value (may be empty)
local function parse_banner_labeled_fields(data)
  local info = {}
  for line in (data .. "\n"):gmatch("([^\r\n]+)") do
    local label, value = line:match("^%s*([%w_ ]+):%s*(.-)%s*$")
    if label and value and value ~= "" then
      local canon = BANNER_LABEL_MAP[label:lower():gsub("%s+$", "")]
      if canon then
        info[canon] = value
      end
    end
  end
  return info
end
```

- [ ] **Step 4: Use banner-label parsing as the primary device_info source**

In `ff-hse-discover-improved.nse`, in the banner branch of `action` (currently
around lines 429-451), replace the structured-parse block:
```lua
    -- Parse structured device info
    local device_info
    if port_num == HSE_MA_PORT then
      device_info = parse_ma_response(banner_data)
    else
      device_info = parse_sm_identify_response(banner_data)
    end

    if device_info and next(device_info) then
      result["device_info"] = device_info
      local summary = summarize_device_info(device_info)
      if summary then
        stdnse.debug1("Device info: %s", summary)
      end
    elseif #hse_strings > 0 then
      -- Fall back to raw strings as device info if structured parse failed
      -- but we found HSE-relevant text
      local fallback_info = {}
      for i, s in ipairs(hse_strings) do
        fallback_info["field_" .. i] = s
      end
      result["device_info"] = fallback_info
    end
```
with:
```lua
    -- Prefer named fields parsed from the labeled ASCII banner.
    local device_info = parse_banner_labeled_fields(banner_data)

    -- If the banner was not labeled text, fall back to binary structured parse.
    if not next(device_info) then
      if port_num == HSE_MA_PORT then
        device_info = parse_ma_response(banner_data)
      else
        device_info = parse_sm_identify_response(banner_data)
      end
    end

    if device_info and next(device_info) then
      result["device_info"] = device_info
      local summary = summarize_device_info(device_info)
      if summary then
        stdnse.debug1("Device info: %s", summary)
      end
    elseif #hse_strings > 0 then
      local fallback_info = {}
      for i, s in ipairs(hse_strings) do
        fallback_info["field_" .. i] = s
      end
      result["device_info"] = fallback_info
    end
```

- [ ] **Step 5: Syntax-check then run the test**

Run: `luac -p improved-scripts/lesser-known/ff-hse-discover-improved.nse && cd sandbox/tests && python3 -m pytest test_ffhse.py -v`
Expected: both FF HSE tests PASS; `device name`, `vendor`=`Micro Motion`, `device tag`=`FIC-301` present; profiles differ.

- [ ] **Step 6: Commit**

```bash
git add improved-scripts/lesser-known/ff-hse-discover-improved.nse sandbox/tests/test_ffhse.py
git commit -m "fix(ff-hse): extract named device fields from labeled banner"
```

---

## Task 4: Red Lion privileged test

Red Lion's portrule is pinned to TCP 789; the mock needs root to bind it. Mock
flag is `--model {G307C2,G308C2,G310C2,G315C2}` (not `--profile`).

**Files:**
- Create: `sandbox/tests/test_redlion.py`

- [ ] **Step 1: Write the privileged test**

`sandbox/tests/test_redlion.py`:
```python
import os
import subprocess
import sys
import time

import pytest

from conftest import LESSER, SANDBOX, nmap_scan, _wait_port

SCRIPT = os.path.join(LESSER, "redlion-cr3-info-improved.nse")

pytestmark = pytest.mark.privileged

not_root = os.geteuid() != 0
skip_reason = "needs root to bind privileged TCP 789"


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_redlion_extracts_model(mock_server):
    mock_server("redlion_mock_server.py", 789, "--model", "G310C2")
    fields, out = nmap_scan(789, SCRIPT)
    assert "model" in fields, out
    assert fields["model"] == "G310C2"
    assert "firmware" in fields, out
    assert "vendor" in fields, out
    assert "Red Lion" in fields["vendor"]


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_redlion_models_differ(mock_server):
    m = mock_server("redlion_mock_server.py", 789, "--model", "G310C2")
    a, _ = nmap_scan(789, SCRIPT)
    m.stop()
    mock_server("redlion_mock_server.py", 789, "--model", "G315C2")
    b, _ = nmap_scan(789, SCRIPT)
    assert a.get("model") != b.get("model"), (a, b)
```

- [ ] **Step 2: Run locally (skips without root)**

Run: `cd sandbox/tests && python3 -m pytest test_redlion.py -v`
Expected: 2 SKIPPED with reason "needs root..." on a non-root shell. If you have
sudo locally: `sudo python3 -m pytest test_redlion.py -v` → expected PASS. If it
fails, that is the first real end-to-end signal for Red Lion — debug the script,
do not weaken the test.

- [ ] **Step 3: Commit**

```bash
git add sandbox/tests/test_redlion.py
git commit -m "test: Red Lion privileged mock-driven test (port 789)"
```

---

## Task 5: Standard-7 tests + profile-fidelity sweep

The 7 standard scripts share `ot_mock_servers.py`. This task requires inspecting
that file first, because its actual port map / protocol coverage determines what
can be asserted.

**Files:**
- Create: `sandbox/tests/test_standard.py`

- [ ] **Step 1: Inspect the all-in-one mock**

Run: `python3 sandbox/ot_mock_servers.py --help` and read the top of
`sandbox/ot_mock_servers.py`. Record, for each of the 7 standard protocols
(modbus, fox, pcworx, hartip, iec61850-mms, dnp3-advanced, profinet-cm), whether
`ot_mock_servers.py` serves it and on which port. Expected documented ports from
README: modbus 502, fox 1911, pcworx 1962, hartip 5094, iec61850 102, dnp3 20000,
profinet 34964/udp.

- [ ] **Step 2: Write `test_standard.py` — one test per SUPPORTED protocol**

Use this template per protocol (example: Modbus). Expected fields come from the
README "What Information Can These Scripts Extract?" table. Modbus 502 needs root
(port < 1024) → mark it `privileged` + skipif like Red Lion. Fox/pcworx/hartip/
dnp3 are > 1024 (unprivileged). iec61850 (102) and profinet (34964/udp) need
root / UDP handling — mark `privileged` or `xfail` per what Step 1 reveals.
```python
import os
import pytest
from conftest import SCRIPTS, nmap_scan

MODBUS = os.path.join(SCRIPTS, "modbus-discover-improved.nse")


@pytest.mark.privileged
@pytest.mark.skipif(os.geteuid() != 0, reason="modbus port 502 needs root")
def test_modbus_extracts_device_id(mock_server):
    # Adjust launcher + args to whatever Step 1 shows ot_mock_servers.py expects.
    mock_server("ot_mock_servers.py", 502, "--protocol", "modbus")
    fields, out = nmap_scan(502, MODBUS)
    assert "vendor" in fields or "device id" in fields, out
```
> DECISION RULE: if Step 1 shows `ot_mock_servers.py` does not serve a given
> protocol (or not on a scannable port), mark that protocol's test
> `@pytest.mark.xfail(reason="ot_mock_servers.py lacks faithful <proto> emulation", strict=False)`
> with a one-line note, rather than skipping silently. Every one of the 7 scripts
> gets a test function, even if xfail.

- [ ] **Step 3: Profile-fidelity sweep follow-through**

For any `*_profiles_differ` test from Tasks 1-3 that failed because a mock ignores
its profile on the asserted field, fix the mock so that field varies per profile
(smallest change that makes distinct profiles distinct), then re-run that test to
green. Commit each mock fix separately with `fix(<proto>): vary <field> by profile`.

- [ ] **Step 4: Run the full suite (unprivileged subset)**

Run: `cd sandbox/tests && python3 -m pytest -m "not privileged" -v`
Expected: all non-privileged tests PASS or are declared `xfail`. No unexpected errors.

- [ ] **Step 5: Commit**

```bash
git add sandbox/tests/test_standard.py
git commit -m "test: standard-7 scripts via all-in-one mock (xfail where unsupported)"
```

---

## Task 6: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install nmap and luac
        run: sudo apt-get update && sudo apt-get install -y nmap lua5.4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install test deps
        run: pip install -r sandbox/tests/requirements.txt

      - name: Lua syntax check (all NSE)
        run: |
          set -e
          for f in improved-scripts/*.nse improved-scripts/lesser-known/*.nse; do
            echo "luac -p $f"
            luac -p "$f"
          done

      - name: Run unprivileged tests
        working-directory: sandbox/tests
        run: python3 -m pytest -m "not privileged" -v

      - name: Run privileged tests (root, port < 1024)
        working-directory: sandbox/tests
        run: sudo -E env "PATH=$PATH" python3 -m pytest -m privileged -v
```

- [ ] **Step 2: Verify the workflow lints locally**

Run: `python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"`
Expected: `yaml ok`.

- [ ] **Step 3: Commit and push to trigger CI**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: GitHub Actions — luac syntax gate + pytest suite"
git push -u origin feat/phase1-quality-ci
```
Expected: the Actions run appears on GitHub for branch `feat/phase1-quality-ci`.
Check `gh run list --branch feat/phase1-quality-ci` and `gh run watch` for green.

---

## Task 7: Docs + finish the branch

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a "Testing & CI" section to README.md**

Insert after the existing "Testing with Mock Servers" section:
```markdown
## ✅ Automated Tests & CI

A pytest harness in `sandbox/tests/` boots each mock server and asserts the
matching NSE script extracts the expected fields (and that different device
profiles produce different output). GitHub Actions runs a `luac -p` syntax gate
plus the full suite on every push and pull request.

```bash
cd sandbox/tests
pip install -r requirements.txt
python3 -m pytest -m "not privileged" -v      # 12 scripts, no root needed
sudo python3 -m pytest -m privileged -v        # Red Lion (port 789) + others
```
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document pytest harness and CI"
```

- [ ] **Step 3: Confirm CI is green, then finish the branch**

Run: `gh run list --branch feat/phase1-quality-ci --limit 1`
Expected: latest run `completed  success`.
Then invoke the `superpowers:finishing-a-development-branch` skill to choose
merge / PR / cleanup.

---

## Self-Review Notes

- **Spec coverage:** harness (T1-2,5), FF HSE full named fields + profile diff
  (T3), profile-fidelity sweep (T1-3 assertions + T5 Step 3), Red Lion end-to-end
  (T4), CI with syntax gate + privileged split (T6), standard-7 with xfail
  fallback (T5). All spec sections mapped.
- **Naming consistency:** `mock_server` fixture, `nmap_scan()`, `parse_fields()`,
  `_wait_port()`, module constants `LESSER`/`SCRIPTS`/`SANDBOX` used identically
  across all test files.
- **Known real-bug gates:** profile-difference and Red Lion tests are allowed to
  fail loudly; the plan says fix the code, never weaken the assertion.
```
