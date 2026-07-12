# Phase 3 (Asset-Inventory Pipeline) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standard-library Python package `assetinv` that turns nmap/NSE scan results from the toolkit's 16 discovery scripts into a normalized, CVE-annotated asset inventory, exportable as JSON and CSV.

**Architecture:** A pipeline of small single-responsibility modules — runner (nmap `-oX` or a saved XML) → parser (XML → raw records) → normalizer (per-script labels → canonical Asset) → cve (offline bundle correlation) → export (JSON/CSV) — tied together by a CLI with `scan` and `parse` subcommands. Built test-first; the offline CVE bundle keeps correlation deterministic and CI-testable.

**Tech Stack:** Python 3 standard library only (argparse, xml.etree.ElementTree, json, csv, subprocess, dataclasses). pytest. GitHub Actions.

**Key facts (verified):** nmap `-oX` renders an NSE `stdnse.output_table()` result as a `<script id="..." output="...">` element with `<elem key="Label">value</elem>` children (nested under `<table>` for structured tables). The parser reads the `<elem key>` children, not the text `output` blob. All scripts here emit flat ordered tables. `assetinv` adds NO dependencies.

---

## File Structure

```
asset-inventory/
  assetinv/
    __init__.py          # exports Asset, CveHint, version
    __main__.py          # `python -m assetinv` -> cli.main()
    parser.py            # parse_xml(xml_str) -> list[RawRecord]
    normalizer.py        # normalize(record) -> Asset ; SCRIPT_MAP table
    cve.py               # load_bundle(path)/correlate(asset, bundle)
    export.py            # to_json(assets)/to_csv(assets)
    runner.py            # run_scan(...)/load_xml(path)
    cli.py               # argparse: scan/parse subcommands
    data/ics_cve_hints.json
  tests/
    conftest.py          # mock-launch helper (reuse sandbox pattern)
    fixtures/enip_scan.xml
    test_parser.py test_normalizer.py test_cve.py test_export.py test_integration.py
  README.md
```
Also modify `.github/workflows/ci.yml` (add a pytest step) and top-level `README.md`.

Work on branch `feat/phase3-asset-inventory` (already created; spec committed there).

---

## Task 1: Package scaffold + parser + XML fixture

**Files:**
- Create: `asset-inventory/assetinv/__init__.py`, `asset-inventory/assetinv/parser.py`
- Create: `asset-inventory/tests/fixtures/enip_scan.xml`, `asset-inventory/tests/test_parser.py`

- [ ] **Step 1: Generate the XML fixture from a real mock scan**

Start the EtherNet/IP mock and capture nmap XML (unprivileged, port 44818):
```bash
python3 sandbox/enip_mock_server.py --port 44818 --profile controllogix &
sleep 1
nmap -Pn -sT -p 44818 --script improved-scripts/enip-identity-improved.nse -oX asset-inventory/tests/fixtures/enip_scan.xml 127.0.0.1
pkill -f enip_mock_server
```
Confirm the fixture contains `<script id="enip-identity-improved">` with `<elem key="Product Name">1756-L61/B LOGIX5561</elem>` (and Vendor, Serial Number, etc.). Commit the fixture as-is — it is the parser's ground truth.

- [ ] **Step 2: Write the failing parser test**

`asset-inventory/tests/test_parser.py`:
```python
import os
from assetinv.parser import parse_xml

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "enip_scan.xml")


def test_parse_extracts_script_record():
    with open(FIX) as f:
        records = parse_xml(f.read())
    assert len(records) >= 1
    r = next(r for r in records if r["script"] == "enip-identity-improved")
    assert r["host"] == "127.0.0.1"
    assert r["port"] == 44818
    assert r["protocol"] == "tcp"
    assert r["fields"]["Product Name"] == "1756-L61/B LOGIX5561"
    assert "Vendor" in r["fields"]
    assert "Serial Number" in r["fields"]
```

- [ ] **Step 3: Run to confirm FAIL**

Run: `cd asset-inventory && python3 -m pytest tests/test_parser.py -v`
Expected: FAIL (ModuleNotFoundError: assetinv). Note: run pytest from `asset-inventory/` so `assetinv` is importable (add an empty `asset-inventory/conftest.py` or rely on rootdir insertion; simplest is `pytest` invoked with `asset-inventory` on `sys.path` — set `pythonpath = .` in a `asset-inventory/pytest.ini`).

- [ ] **Step 4: Create `pytest.ini` + `__init__.py`**

`asset-inventory/pytest.ini`:
```ini
[pytest]
pythonpath = .
testpaths = tests
```
`asset-inventory/assetinv/__init__.py`:
```python
"""assetinv: normalize OT NSE scan results into a CVE-annotated asset inventory."""
__version__ = "0.1.0"
```

- [ ] **Step 5: Implement `parser.py`**

```python
import xml.etree.ElementTree as ET


def _script_fields(script_el):
    """Collect {label: value} from a <script>'s <elem key> children.

    Handles both flat <elem key="..."> directly under <script> and children
    nested one level in <table>. Skips keyless <elem>.
    """
    fields = {}
    for elem in script_el.iter("elem"):
        key = elem.get("key")
        if key and elem.text is not None:
            fields[key] = elem.text.strip()
    return fields


def parse_xml(xml_str):
    """Parse nmap -oX output into a list of raw per-(host,port,script) records.

    Each record: {host, port, protocol, script, fields{label: value}}.
    """
    root = ET.fromstring(xml_str)
    records = []
    for host in root.iter("host"):
        addr = None
        for a in host.iter("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        for port in host.iter("port"):
            portid = int(port.get("portid"))
            proto = port.get("protocol")
            for script in port.findall("script"):
                sid = script.get("id")
                fields = _script_fields(script)
                if fields:
                    records.append({
                        "host": addr, "port": portid, "protocol": proto,
                        "script": sid, "fields": fields,
                    })
    return records
```

- [ ] **Step 6: Run test to confirm PASS**

Run: `cd asset-inventory && python3 -m pytest tests/test_parser.py -v`
Expected: PASS. If `<elem>` values differ from the fixture, fix the assertion to the fixture's real content (the fixture is ground truth), not the parser.

- [ ] **Step 7: Commit**

```bash
git add asset-inventory/assetinv/__init__.py asset-inventory/assetinv/parser.py asset-inventory/pytest.ini asset-inventory/tests/test_parser.py asset-inventory/tests/fixtures/enip_scan.xml
git commit -m "feat(assetinv): nmap XML parser + fixture

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Canonical Asset + normalizer (all 16 scripts)

**Files:**
- Create: `asset-inventory/assetinv/normalizer.py`
- Create: `asset-inventory/tests/test_normalizer.py`
- Modify: `asset-inventory/assetinv/__init__.py` (export `Asset`)

- [ ] **Step 1: Write the failing normalizer test**

`asset-inventory/tests/test_normalizer.py`:
```python
from assetinv.normalizer import normalize


def test_normalize_enip():
    rec = {"host": "127.0.0.1", "port": 44818, "protocol": "tcp",
           "script": "enip-identity-improved",
           "fields": {"Vendor": "Rockwell Automation/Allen-Bradley (1)",
                      "Product Name": "1756-L61/B LOGIX5561",
                      "Serial Number": "0x00C0FFEE", "Revision": "20.11",
                      "Device Type": "Programmable Logic Controller (14)"}}
    a = normalize(rec)
    assert a.vendor == "Rockwell Automation/Allen-Bradley (1)"
    assert a.product == "1756-L61/B LOGIX5561"
    assert a.firmware == "20.11"
    assert a.serial == "0x00C0FFEE"
    assert a.device == "EtherNet/IP CIP"
    assert a.raw["Device Type"] == "Programmable Logic Controller (14)"


def test_normalize_s7():
    rec = {"host": "10.0.0.9", "port": 102, "protocol": "tcp",
           "script": "s7comm-plus-info-improved",
           "fields": {"Module": "6ES7 515-2AM01-0AB0", "Version": "2.9.2",
                      "Module Type": "CPU 1515-2 PN", "System Name": "PLC_1500",
                      "Serial Number": "S C-L2X920551024"}}
    a = normalize(rec)
    assert a.product == "6ES7 515-2AM01-0AB0"
    assert a.firmware == "2.9.2"
    assert a.device_type == "CPU 1515-2 PN"
    assert a.raw["System Name"] == "PLC_1500"


def test_normalize_unknown_script_is_lossless():
    rec = {"host": "x", "port": 1, "protocol": "tcp", "script": "future-proto",
           "fields": {"Weird Label": "v"}}
    a = normalize(rec)
    assert a.raw["Weird Label"] == "v"
    assert a.vendor is None and a.product is None
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd asset-inventory && python3 -m pytest tests/test_normalizer.py -v` → FAIL (no module).

- [ ] **Step 3: Implement `normalizer.py`**

```python
from dataclasses import dataclass, field


@dataclass
class Asset:
    host: str
    port: int
    protocol: str
    script: str
    device: str = ""
    vendor: str = None
    product: str = None
    firmware: str = None
    serial: str = None
    device_type: str = None
    raw: dict = field(default_factory=dict)
    cve_hints: list = field(default_factory=list)


# Per-script: human device label + {canonical field: source label}.
SCRIPT_MAP = {
    "enip-identity-improved": ("EtherNet/IP CIP", {
        "vendor": "Vendor", "product": "Product Name",
        "firmware": "Revision", "serial": "Serial Number",
        "device_type": "Device Type"}),
    "bacnet-discover-improved": ("BACnet/IP", {
        "vendor": "Vendor", "product": "Model Name", "firmware": "Firmware"}),
    "s7comm-plus-info-improved": ("S7comm-plus", {
        "product": "Module", "device_type": "Module Type",
        "firmware": "Version", "serial": "Serial Number"}),
    "modbus-discover-improved": ("Modbus", {"product": "Slave ID data"}),
    "fox-info-improved": ("Fox", {"firmware": "fox.version"}),
    "pcworx-info-improved": ("PCWorx", {
        "product": "PLC Type", "firmware": "Firmware Version"}),
    "hartip-info-improved": ("HART-IP", {"vendor": "Manufacturer Id"}),
    "iec61850-mms-improved": ("IEC 61850 MMS", {"vendor": "VendorName"}),
    "profinet-cm-lookup-improved": ("PROFINET CM", {"product": "deviceName"}),
    "dnp3-advanced-info": ("DNP3", {}),
    "gesrtp-info-improved": ("GE SRTP", {
        "product": "PLC Model", "firmware": "Firmware Version",
        "device_type": "CPU Type"}),
    "opcua-discovery-improved": ("OPC UA", {"product": "Application Name"}),
    "melsecq-info-improved": ("MELSEC-Q", {
        "product": "PLC Type", "firmware": "Firmware"}),
    "proconos-info-improved": ("ProConOS", {
        "product": "PLC Model", "firmware": "Runtime"}),
    "ff-hse-discover-improved": ("FF HSE", {
        "vendor": "Vendor", "product": "Device Name",
        "firmware": "Software Revision"}),
    "redlion-cr3-info-improved": ("Red Lion", {
        "vendor": "Manufacturer", "product": "Model",
        "firmware": "Firmware Version"}),
}


def normalize(record):
    """Map a raw parser record to a canonical Asset (lossless via .raw)."""
    device, mapping = SCRIPT_MAP.get(record["script"], ("", {}))
    fields = dict(record["fields"])
    a = Asset(host=record["host"], port=record["port"],
              protocol=record["protocol"], script=record["script"],
              device=device, raw=fields)
    for canon, label in mapping.items():
        if label in fields:
            setattr(a, canon, fields[label])
    return a
```

- [ ] **Step 4: Export `Asset`; run tests**

Add to `asset-inventory/assetinv/__init__.py`:
```python
from assetinv.normalizer import Asset  # noqa: E402,F401
```
Run: `cd asset-inventory && python3 -m pytest tests/test_normalizer.py -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add asset-inventory/assetinv/normalizer.py asset-inventory/assetinv/__init__.py asset-inventory/tests/test_normalizer.py
git commit -m "feat(assetinv): canonical Asset + per-script normalizer (16 scripts)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: CVE bundle + correlator

**Files:**
- Create: `asset-inventory/assetinv/cve.py`, `asset-inventory/assetinv/data/ics_cve_hints.json`
- Create: `asset-inventory/tests/test_cve.py`

- [ ] **Step 1: Write the failing CVE test**

`asset-inventory/tests/test_cve.py`:
```python
import re
from assetinv.cve import load_bundle, correlate
from assetinv.normalizer import Asset


def test_bundle_loads_and_matches_controllogix():
    bundle = load_bundle()  # default path -> assetinv/data/ics_cve_hints.json
    a = Asset(host="h", port=44818, protocol="tcp",
              script="enip-identity-improved",
              vendor="Rockwell Automation/Allen-Bradley (1)",
              product="1756-L61/B LOGIX5561")
    hints = correlate(a, bundle)
    assert len(hints) >= 1
    assert all(re.match(r"^CVE-\d{4}-\d+$", h["id"]) for h in hints)
    assert all("severity" in h and "summary" in h for h in hints)


def test_no_match_returns_empty():
    bundle = load_bundle()
    a = Asset(host="h", port=1, protocol="tcp", script="x",
              vendor="Nonexistent Vendor", product="ZZZ-0000")
    assert correlate(a, bundle) == []
```

- [ ] **Step 2: Run to confirm FAIL** → `cd asset-inventory && python3 -m pytest tests/test_cve.py -v`

- [ ] **Step 3: Create the seed bundle**

`asset-inventory/assetinv/data/ics_cve_hints.json` — seed with REAL, verifiable ICS CVEs mapped to the mock profiles' products. Curate each `id` from a real CISA ICS advisory (do not invent ids). Cover at least ControlLogix (for the integration test), Siemens S7-1500, and one BACnet BAS vendor. Shape:
```json
[
  {
    "vendor": "Rockwell",
    "product_match": "1756-L6",
    "firmware_match": null,
    "cves": [
      {"id": "CVE-XXXX-XXXX", "severity": "high",
       "summary": "<one-line, from the advisory>",
       "source": "CISA ICSA-XX-XXX-XX"}
    ]
  }
]
```
> The implementer MUST replace `CVE-XXXX-XXXX`/`ICSA-...` with real advisory data (e.g. look up a genuine ControlLogix 1756-L6x CVE). The tests assert CVE-id FORMAT and match behavior, not a specific id, so any real ControlLogix CVE satisfies them — but the ids must be real, not fabricated.

- [ ] **Step 4: Implement `cve.py`**

```python
import json
import os

_DEFAULT = os.path.join(os.path.dirname(__file__), "data", "ics_cve_hints.json")

DISCLAIMER = "hints only; verify against vendor/CISA advisories"


def load_bundle(path=None):
    with open(path or _DEFAULT) as f:
        return json.load(f)


def _matches(entry, asset):
    hay_vendor = (asset.vendor or "").lower()
    hay_product = (asset.product or "").lower()
    if entry["vendor"].lower() not in hay_vendor and \
       entry["vendor"].lower() not in hay_product:
        return False
    if entry["product_match"].lower() not in hay_product:
        return False
    fm = entry.get("firmware_match")
    if fm and fm.lower() not in (asset.firmware or "").lower():
        return False
    return True


def correlate(asset, bundle):
    """Return the list of CVE-hint dicts whose entry matches the asset."""
    hints = []
    for entry in bundle:
        if _matches(entry, asset):
            hints.extend(entry["cves"])
    return hints
```

- [ ] **Step 5: Run test to confirm PASS** → both tests green.

- [ ] **Step 6: Commit**

```bash
git add asset-inventory/assetinv/cve.py asset-inventory/assetinv/data/ics_cve_hints.json asset-inventory/tests/test_cve.py
git commit -m "feat(assetinv): offline ICS CVE bundle + correlator

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Exporters (JSON + CSV)

**Files:**
- Create: `asset-inventory/assetinv/export.py`
- Create: `asset-inventory/tests/test_export.py`

- [ ] **Step 1: Write the failing test**

`asset-inventory/tests/test_export.py`:
```python
import json
from assetinv.normalizer import Asset
from assetinv.export import to_json, to_csv


def _asset():
    a = Asset(host="127.0.0.1", port=44818, protocol="tcp",
              script="enip-identity-improved", device="EtherNet/IP CIP",
              vendor="Rockwell", product="1756-L61", firmware="20.11",
              serial="0x00C0FFEE", raw={"Device State": "3"})
    a.cve_hints = [{"id": "CVE-2020-0001", "severity": "high",
                    "summary": "x", "source": "CISA"}]
    return a


def test_to_json_roundtrips():
    data = json.loads(to_json([_asset()]))
    assert data["assets"][0]["product"] == "1756-L61"
    assert data["assets"][0]["cve_hints"][0]["id"] == "CVE-2020-0001"
    assert "disclaimer" in data


def test_to_csv_has_header_and_row():
    csv_text = to_csv([_asset()])
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("host,port,protocol,device,vendor,product")
    assert "1756-L61" in lines[1]
    assert "CVE-2020-0001" in lines[1]
```

- [ ] **Step 2: Run to confirm FAIL**

- [ ] **Step 3: Implement `export.py`**

```python
import csv
import io
import json
from dataclasses import asdict

from assetinv.cve import DISCLAIMER

_CSV_COLS = ["host", "port", "protocol", "device", "vendor", "product",
             "firmware", "serial", "device_type", "script", "cves"]


def to_json(assets):
    return json.dumps({
        "disclaimer": DISCLAIMER,
        "count": len(assets),
        "assets": [asdict(a) for a in assets],
    }, indent=2)


def to_csv(assets):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV_COLS)
    for a in assets:
        cves = ";".join(h["id"] for h in a.cve_hints)
        w.writerow([a.host, a.port, a.protocol, a.device, a.vendor or "",
                    a.product or "", a.firmware or "", a.serial or "",
                    a.device_type or "", a.script, cves])
    return buf.getvalue()
```

- [ ] **Step 4: Run test to confirm PASS**

- [ ] **Step 5: Commit**

```bash
git add asset-inventory/assetinv/export.py asset-inventory/tests/test_export.py
git commit -m "feat(assetinv): JSON + CSV exporters

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Runner + CLI

**Files:**
- Create: `asset-inventory/assetinv/runner.py`, `asset-inventory/assetinv/cli.py`, `asset-inventory/assetinv/__main__.py`
- Create: `asset-inventory/tests/test_cli.py`

- [ ] **Step 1: Write the failing CLI test (parse path, no nmap needed)**

`asset-inventory/tests/test_cli.py`:
```python
import json
import os
from assetinv.cli import main

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "enip_scan.xml")


def test_cli_parse_json(capsys):
    rc = main(["parse", FIX, "--cve", "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    asset = next(a for a in data["assets"]
                 if a["script"] == "enip-identity-improved")
    assert asset["product"] == "1756-L61/B LOGIX5561"
    # ControlLogix has a seeded CVE hint
    assert len(asset["cve_hints"]) >= 1
```

- [ ] **Step 2: Run to confirm FAIL**

- [ ] **Step 3: Implement `runner.py`**

```python
import subprocess


def run_scan(target, ports, script_path, udp=False, timeout=180):
    """Run nmap with one or more NSE scripts and return the -oX XML string."""
    proto = "-sU" if udp else "-sT"
    cmd = ["nmap", "-Pn", proto, "-p", str(ports), "--script", script_path,
           "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.stdout


def load_xml(path):
    with open(path) as f:
        return f.read()
```

- [ ] **Step 4: Implement `cli.py`**

```python
import argparse
import sys

from assetinv import runner, parser as xmlparser, normalizer, cve, export


def _build(records, want_cve):
    bundle = cve.load_bundle() if want_cve else None
    assets = []
    for rec in records:
        a = normalizer.normalize(rec)
        if bundle is not None:
            a.cve_hints = cve.correlate(a, bundle)
        assets.append(a)
    return assets


def _emit(assets, fmt, out):
    text = export.to_json(assets) if fmt == "json" else export.to_csv(assets)
    if out:
        with open(out, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="assetinv",
        description="OT asset inventory from NSE scan results")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="run nmap and build an inventory")
    ps.add_argument("target")
    ps.add_argument("--ports", default="44818")
    ps.add_argument("--script", required=True,
                    help="path(s) to NSE script(s) for --script")
    ps.add_argument("--udp", action="store_true")

    pp = sub.add_parser("parse", help="build an inventory from saved nmap XML")
    pp.add_argument("xml")

    for p in (ps, pp):
        p.add_argument("--cve", action="store_true")
        p.add_argument("--format", choices=["json", "csv"], default="json")
        p.add_argument("-o", "--out")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        xml = runner.run_scan(args.target, args.ports, args.script, args.udp)
    else:
        xml = runner.load_xml(args.xml)
    records = xmlparser.parse_xml(xml)
    assets = _build(records, args.cve)
    _emit(assets, args.format, args.out)
    return 0
```

- [ ] **Step 5: Implement `__main__.py`**

```python
import sys
from assetinv.cli import main

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run test to confirm PASS** → `cd asset-inventory && python3 -m pytest tests/test_cli.py -v`

- [ ] **Step 7: Commit**

```bash
git add asset-inventory/assetinv/runner.py asset-inventory/assetinv/cli.py asset-inventory/assetinv/__main__.py asset-inventory/tests/test_cli.py
git commit -m "feat(assetinv): nmap runner + scan/parse CLI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: End-to-end integration test + CI

**Files:**
- Create: `asset-inventory/tests/conftest.py`, `asset-inventory/tests/test_integration.py`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write `conftest.py` (mock launcher)**

`asset-inventory/tests/conftest.py`:
```python
import os
import socket
import subprocess
import sys
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SANDBOX = os.path.join(REPO, "sandbox")
SCRIPTS = os.path.join(REPO, "improved-scripts")


def _wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


@pytest.fixture
def enip_mock():
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SANDBOX, "enip_mock_server.py"),
         "--port", "44818", "--profile", "controllogix"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_port(44818):
        proc.terminate()
        raise RuntimeError("enip mock never opened 44818")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
```

- [ ] **Step 2: Write the integration test**

`asset-inventory/tests/test_integration.py`:
```python
import json
import os

from assetinv.cli import main

SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "improved-scripts")


def test_end_to_end_scan_with_cve(enip_mock, capsys):
    script = os.path.join(SCRIPTS, "enip-identity-improved.nse")
    rc = main(["scan", "127.0.0.1", "--ports", "44818",
               "--script", script, "--cve", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    asset = next(a for a in data["assets"]
                 if a["script"] == "enip-identity-improved")
    assert asset["device"] == "EtherNet/IP CIP"
    assert "1756-L61" in asset["product"]
    assert "Allen-Bradley" in asset["vendor"]
    assert len(asset["cve_hints"]) >= 1
    assert asset["cve_hints"][0]["id"].startswith("CVE-")
    assert data["disclaimer"]
```

- [ ] **Step 3: Run the full package suite locally**

Run: `cd asset-inventory && python3 -m pytest -v`
Expected: all tests PASS (parser, normalizer, cve, export, cli, integration). The integration test starts the real enip mock and runs real nmap — unprivileged, no root.

- [ ] **Step 4: Add a CI step**

In `.github/workflows/ci.yml`, after the existing "Run privileged tests" step, add:
```yaml
      - name: Run asset-inventory pipeline tests
        working-directory: asset-inventory
        run: python3 -m pytest -v
```
(The `nmap` install and Python setup already exist earlier in the job; `assetinv` needs no extra deps.)

- [ ] **Step 5: Verify YAML + commit**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"`
```bash
git add asset-inventory/tests/conftest.py asset-inventory/tests/test_integration.py .github/workflows/ci.yml
git commit -m "test(assetinv): end-to-end integration test + CI step

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Docs + finish the branch

**Files:**
- Create: `asset-inventory/README.md`
- Modify: top-level `README.md`

- [ ] **Step 1: Write `asset-inventory/README.md`**

Document: what it does (pipeline diagram), install (none — stdlib), the `scan` and `parse` subcommands with examples, the canonical Asset schema, the offline CVE bundle + its non-authoritative framing + how to update it, and how to run the tests.

- [ ] **Step 2: Add an "Asset Inventory" section to the top-level `README.md`**

After the "Automated Tests & CI" section, add a short section pointing to `asset-inventory/` with a one-line pipeline description and a `python -m assetinv parse scan.xml --cve` example. Note it is Phase 3 of the project.

- [ ] **Step 3: Commit**

```bash
git add asset-inventory/README.md README.md
git commit -m "docs: document the asset-inventory pipeline (Phase 3)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 4: Full local verification**

Run: `cd asset-inventory && python3 -m pytest -q` → all green.
Run (from repo root): `cd sandbox/tests && python3 -m pytest -m "not privileged" -q` → confirm Phase 1/2 suite still green (unchanged).

- [ ] **Step 5: Push and confirm CI green**

```bash
git push -u origin feat/phase3-asset-inventory
gh run list --branch feat/phase3-asset-inventory --limit 1
```
Watch (`gh run watch <id> --exit-status`). CI runs luac gate + protocol tests (unchanged) + the new asset-inventory suite. Expected: green.

- [ ] **Step 6: Finish the branch**

Invoke `superpowers:finishing-a-development-branch` (base `main`).

---

## Self-Review Notes

- **Spec coverage:** runner+CLI (Task 5), parser (Task 1), normalizer+schema (Task 2), CVE bundle+correlator (Task 3), exporters (Task 4), integration test + CI (Task 6), docs (Task 7). All spec modules mapped.
- **Naming consistency:** `parse_xml`, `normalize`/`Asset`/`SCRIPT_MAP`, `load_bundle`/`correlate`, `to_json`/`to_csv`, `run_scan`/`load_xml`, `main` — used identically across tasks and tests. CSV columns fixed in `export.py`.
- **Real-data gate:** the CVE bundle must use REAL advisory CVE ids (Task 3 note); tests assert id FORMAT + match behavior, not fabricated specifics. The parser fixture is captured from a real mock scan (Task 1), not hand-authored.
- **No new dependencies:** stdlib only; integration test is unprivileged (enip TCP 44818).
