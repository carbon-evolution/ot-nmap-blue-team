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
