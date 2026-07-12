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
