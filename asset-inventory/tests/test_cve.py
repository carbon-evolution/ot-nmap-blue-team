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


def test_matches_s7_1500():
    bundle = load_bundle()
    a = Asset(host="h", port=102, protocol="tcp",
              script="s7comm-plus-info-improved",
              vendor=None, product="6ES7 515-2AM01-0AB0")
    hints = correlate(a, bundle)
    assert any(h["id"] == "CVE-2020-15782" for h in hints)


def test_no_match_returns_empty():
    bundle = load_bundle()
    a = Asset(host="h", port=1, protocol="tcp", script="x",
              vendor="Nonexistent Vendor", product="ZZZ-0000")
    assert correlate(a, bundle) == []
