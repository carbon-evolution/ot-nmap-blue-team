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


def test_cli_parse_csv(capsys):
    rc = main(["parse", FIX, "--format", "csv"])
    assert rc == 0
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert lines[0].startswith("host,port,protocol,device,vendor,product")
    assert any("1756-L61/B LOGIX5561" in line for line in lines[1:])
