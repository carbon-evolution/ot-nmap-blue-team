# assetinv — OT Asset-Inventory Pipeline

Phase 3 of the OT Nmap Blue Team toolkit. Turns raw NSE scan results from the
16 discovery scripts into a normalized, CVE-annotated **asset inventory**,
exportable as JSON or CSV.

```
target/subnet ─▶ runner ─▶ nmap -oX (NSE scripts) ─▶ parser ─▶ normalizer ─▶ cve ─▶ export ─▶ inventory.json / .csv
                   │                                     ▲
                   └── OR: parse <saved nmap.xml> ───────┘
```

Standard library only — no dependencies to install.

## Usage

```bash
# Parse a previously captured nmap XML into a CVE-annotated JSON inventory
python3 -m assetinv parse scan.xml --cve

# Live scan of a host with one (or more) NSE scripts, CSV to a file
python3 -m assetinv scan 10.0.0.5 --ports 44818 \
    --script ../improved-scripts/enip-identity-improved.nse \
    --cve --format csv -o inventory.csv

# UDP protocols (BACnet, PROFINET) need root for -sU
sudo python3 -m assetinv scan 10.0.0.5 --ports 47808 --udp \
    --script ../improved-scripts/bacnet-discover-improved.nse --cve
```

Capture nmap XML yourself for the `parse` path with `nmap ... -oX scan.xml`.
`--script` accepts a path, a comma-separated list of paths, or an nmap script
category, exactly as nmap's `--script`.

## Canonical Asset schema

Each discovered device becomes one `Asset`:

| field | meaning |
|-------|---------|
| `host`, `port`, `protocol` | where it was found |
| `script` | the NSE script that produced it |
| `device` | protocol/device label (e.g. "EtherNet/IP CIP") |
| `vendor`, `product`, `firmware`, `serial`, `device_type` | normalized identity |
| `raw` | every original NSE label→value (nothing is lost) |
| `cve_hints` | CVE hints attached when `--cve` is used |

The per-script label→canonical mapping lives in `assetinv/normalizer.py`
(`SCRIPT_MAP`). An unknown script still yields an Asset with its data under
`raw`, so new scripts degrade gracefully rather than being dropped.

## CVE hints (non-authoritative)

`--cve` correlates each asset against an **offline curated bundle**,
`assetinv/data/ics_cve_hints.json`, matching on vendor-specific product order
numbers (e.g. `1756-L6`, `6ES7 515`). Every export carries the disclaimer:

> hints only; verify against vendor/CISA advisories

These are triage pointers, not authoritative findings. The seed bundle covers a
handful of well-known ICS CVEs (Rockwell Logix, Siemens S7-1200/1500). **To
update:** edit `assetinv/data/ics_cve_hints.json` — add entries of
`{vendor, product_match, firmware_match?, cves:[{id, severity, summary, source}]}`
with real advisory data.

## Tests

```bash
cd asset-inventory
python3 -m pytest -v
```

Unit tests cover the parser (against a committed fixture captured from a real
mock scan), normalizer, CVE correlator, and exporters. One unprivileged
end-to-end integration test starts the EtherNet/IP mock, runs a real nmap scan,
and asserts the pipeline produces the ControlLogix asset with its CVE hint. CI
runs the whole suite on every push.
