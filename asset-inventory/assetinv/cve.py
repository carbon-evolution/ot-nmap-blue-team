"""Offline ICS CVE-hint bundle loading and correlation.

The bundle is a curated, NON-AUTHORITATIVE starter set of well-known ICS CVEs
keyed to vendor/product substrings. Hints are pointers for triage, not a
substitute for checking vendor/CISA advisories against the exact device and
firmware. Update assetinv/data/ics_cve_hints.json manually.
"""
import json
import os

_DEFAULT = os.path.join(os.path.dirname(__file__), "data", "ics_cve_hints.json")

DISCLAIMER = "hints only; verify against vendor/CISA advisories"


def load_bundle(path=None):
    """Load the CVE-hint bundle (defaults to the packaged data file)."""
    with open(path or _DEFAULT) as f:
        return json.load(f)


def _matches(entry, asset):
    product = (asset.product or "").lower()
    # product_match is the primary signal (vendor-specific order numbers like
    # "6ES7 515" or "1756-L6").
    if entry["product_match"].lower() not in product:
        return False
    # Vendor is a confirming check only when the asset carries one; some scripts
    # (e.g. S7comm SZL) emit no vendor field, so rely on product_match alone.
    vendor = (asset.vendor or "").lower()
    ev = entry["vendor"].lower()
    if vendor and ev not in vendor and ev not in product:
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
