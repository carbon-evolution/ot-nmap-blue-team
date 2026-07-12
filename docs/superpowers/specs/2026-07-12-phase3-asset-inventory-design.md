# Phase 3 Design — Asset-Inventory Pipeline

**Status:** Approved 2026-07-12. Third and final phase, following
[Phase 1](2026-07-11-phase1-quality-ci-design.md) (harness + CI) and
[Phase 2](2026-07-12-phase2-new-protocols-design.md) (3 new protocols), both
merged to `main`.

## Goal

Turn raw NSE scan results from the toolkit's 16 discovery scripts into a
normalized, CVE-annotated **asset inventory**, exportable as JSON and CSV, via
a small Python package. This is the "blue-team output" story: from
"which scripts extract what" to "here is your OT asset list, with risk hints."

Full pipeline, approved scope: a scan-orchestration wrapper + normalized
JSON/CSV asset-inventory output + CVE-correlation hints from an offline curated
bundle (keyless, deterministic, CI-testable — matching the whole toolkit's
ethos). No live/online CVE lookup.

## Architecture

A new importable Python package under `asset-inventory/` (package `assetinv/`),
decomposed into single-responsibility modules that each have a clear interface
and are independently testable.

```
target/subnet ─▶ runner ─▶ nmap -oX (16 NSE scripts) ─▶ parser ─▶ normalizer ─▶ cve ─▶ export ─▶ inventory.json / .csv
                   │                                        ▲
                   └── OR: --from-xml <saved nmap.xml> ─────┘
```

Parsing nmap's structured `-oX` XML (where an NSE `stdnse.output_table()`
result appears as a `<script>` element with `<elem key="Label">value</elem>`
children, possibly nested in `<table>`) is the key decision: it is
deterministic and testable, avoiding fragile text scraping of the `| Label:
value` block.

## Modules (`assetinv/`)

Each module is small, with one responsibility and a well-defined interface:

- `runner.py` — `run_scan(target, ports, scripts, udp=False) -> str` builds and
  executes `nmap -Pn -oX - --script <set> -p <ports> <target>` and returns the
  XML; `load_xml(path) -> str` reads a saved XML file. The runner does not
  parse; it only produces XML.
- `parser.py` — `parse_xml(xml_str) -> list[dict]` walks the nmap XML and yields
  one raw record per (host, port) that carried script output: `{host, port,
  protocol, script, fields{label: value}}`. Handles both flat `<elem>` and
  nested `<table>` script output.
- `normalizer.py` — `normalize(record) -> Asset` maps each script's specific
  labels into the canonical schema via a per-script mapping table. Unmapped
  labels are preserved under `raw`.
- `cve.py` — `load_bundle(path) -> Bundle` and `correlate(asset, bundle) ->
  list[CveHint]`; matches asset vendor/product/firmware against bundle entries
  (case-insensitive substring, optional firmware match).
- `export.py` — `to_json(assets) -> str` (nested) and `to_csv(assets) -> str`
  (one flattened row per asset, CVE ids joined).
- `cli.py` — argparse CLI with two subcommands:
  - `scan <target> [--ports P] [--udp] [--cve] [--format json|csv] [-o FILE]`
  - `parse <nmap.xml> [--cve] [--format json|csv] [-o FILE]`
  - `python -m assetinv ...` entry point via `__main__.py`.

## Canonical Asset schema

One `Asset` per (host, port, device), a dataclass (or plain dict) with:

| field | meaning |
|-------|---------|
| `host` | IP/hostname |
| `port` | port number |
| `protocol` | tcp/udp |
| `script` | NSE script that produced it (e.g. `enip-identity-improved`) |
| `device` | short protocol/device label (e.g. "EtherNet/IP CIP") |
| `vendor` | normalized vendor string |
| `product` | model / product / module (canonicalized) |
| `firmware` | firmware / version string |
| `serial` | serial number if present |
| `device_type` | device category if present |
| `raw` | dict of all original script labels→values (nothing lost) |
| `cve_hints` | list attached by the correlator (empty unless `--cve`) |

The per-script label→canonical mapping is a single table in `normalizer.py`,
e.g. `enip-identity-improved`: `product` ← `Product Name`, `vendor` ← `Vendor`,
`firmware` ← `Revision`, `serial` ← `Serial Number`; `s7comm-plus-info-improved`:
`product` ← `Module`, `device_type` ← `Module Type`, `firmware` ← `Version`,
`serial` ← `Serial Number`, plus `System Name` in `raw`; `bacnet-discover-improved`:
`vendor` ← `Vendor`, `product` ← `Model Name`, `firmware` ← `Firmware`; and so on
for all 16 scripts. Any script/label not in the table still yields an Asset with
its data under `raw` (graceful, lossless).

## CVE bundle

`assetinv/data/ics_cve_hints.json` — a JSON list of entries:
```json
{
  "vendor": "Rockwell Automation",
  "product_match": "1756-L6",
  "firmware_match": null,
  "cves": [
    {"id": "CVE-2017-14022", "severity": "high",
     "summary": "Improper input validation in ControlLogix ...",
     "source": "CISA ICSA-17-XXX"}
  ]
}
```
Seeded with a handful of **real, well-known ICS CVEs** mapped to the products
the mock profiles emit (e.g. Rockwell ControlLogix `1756-L6x`, Siemens S7-1500
`6ES7 515`, Automated Logic BAS) so the pipeline demonstrably produces hints and
the correlation is CI-testable against the mocks. `correlate()` matches
`vendor` AND `product_match` (case-insensitive substring) against the asset,
with an optional `firmware_match`. Output is explicitly framed as
**non-authoritative hints** — every export notes "hints only; verify against
vendor/CISA advisories." Updating the bundle is a documented manual step.

## CLI examples

```bash
# Live scan of a host, JSON with CVE hints
python -m assetinv scan 10.0.0.5 --cve -o inventory.json

# Parse a previously captured nmap XML into CSV
python -m assetinv parse scan.xml --cve --format csv -o inventory.csv
```

## Testing & CI

Under `asset-inventory/tests/` (pytest):
- **Unit** — `parser` against a committed nmap-XML fixture (captured from a real
  mock scan) → asserts extracted records; `normalizer` label-mapping per script;
  `cve.correlate` (asset → expected hints, and non-match → none); `export`
  JSON/CSV shape.
- **Integration (unprivileged, end-to-end)** — start the EtherNet/IP mock
  (`sandbox/enip_mock_server.py`, TCP 44818, no root), run `assetinv scan
  127.0.0.1 -p 44818 --cve`, assert the inventory contains the ControlLogix
  asset (vendor/product/serial) AND its seeded CVE hint. Proves runner → nmap →
  parse → normalize → correlate → export without root. (Privileged protocols use
  the same code path; one unprivileged protocol validates the pipeline.)
- **CI** — add a step to `.github/workflows/ci.yml` running
  `pytest asset-inventory/tests`. The existing luac gate and protocol tests are
  unaffected. `assetinv` uses only the Python standard library (argparse,
  xml.etree, json, csv, subprocess) — no new dependencies.

## File Structure

- `asset-inventory/assetinv/__init__.py`, `__main__.py`, `runner.py`,
  `parser.py`, `normalizer.py`, `cve.py`, `export.py`, `cli.py`
- `asset-inventory/assetinv/data/ics_cve_hints.json`
- `asset-inventory/tests/` — `conftest.py` (reuse the mock-launch pattern),
  `fixtures/enip_scan.xml`, `test_parser.py`, `test_normalizer.py`,
  `test_cve.py`, `test_export.py`, `test_integration.py`
- `asset-inventory/README.md` — usage
- Modify `.github/workflows/ci.yml` (add the pytest step) and top-level
  `README.md` (document the pipeline).

## Non-goals (YAGNI)

- No live/online CVE lookup (offline bundle only).
- No HTML/PDF reporting, dashboards, or diffing between scans.
- No scan scheduling, credentialed/authenticated scanning, or active exploitation.
- No new third-party dependencies (standard library only).

## Risks

- **nmap XML shape** — nested `<table>` vs flat `<elem>` output varies by script;
  the parser must handle both. Mitigated by the committed XML fixture + the
  live integration test.
- **CVE bundle staleness** — curated hints go out of date; mitigated by the
  explicit "non-authoritative, verify against advisories" framing and a
  documented update step. This is a feature (portable, deterministic), not a bug.
- **Label-mapping drift** — if a script's output labels change, the normalizer
  mapping must follow; unmapped labels degrade gracefully to `raw` rather than
  being lost, and normalizer unit tests pin the mapping.
