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
