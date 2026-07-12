"""Export a list of Assets as JSON (nested) or CSV (flat rows)."""
import csv
import io
import json
from dataclasses import asdict

from assetinv.cve import DISCLAIMER

_CSV_COLS = ["host", "port", "protocol", "device", "vendor", "product",
             "firmware", "serial", "device_type", "script", "cves"]


def to_json(assets):
    """Full nested inventory with a disclaimer and count."""
    return json.dumps({
        "disclaimer": DISCLAIMER,
        "count": len(assets),
        "assets": [asdict(a) for a in assets],
    }, indent=2)


def to_csv(assets):
    """One flattened row per asset; CVE ids are ';'-joined in the cves column."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV_COLS)
    for a in assets:
        cves = ";".join(h["id"] for h in a.cve_hints)
        w.writerow([a.host, a.port, a.protocol, a.device, a.vendor or "",
                    a.product or "", a.firmware or "", a.serial or "",
                    a.device_type or "", a.script, cves])
    return buf.getvalue()
