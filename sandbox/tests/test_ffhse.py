import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "ff-hse-discover-improved.nse")


def test_ffhse_extracts_named_fields(mock_server):
    mock_server("ffhse_mock_server.py", 1089, "--profile", "flow")
    fields, out = nmap_scan(1089, SCRIPT)
    # Named fields, not generic field_1/field_2
    assert "field_1" not in fields, out
    assert "device name" in fields, out
    assert "vendor" in fields, out
    assert "device tag" in fields, out
    assert "hse version" in fields, out
    assert "software revision" in fields, out
    assert "stack" in fields, out
    assert "mac" in fields, out
    # Values come from the 'flow' profile
    assert fields["vendor"] == "Micro Motion"
    assert fields["device tag"] == "FIC-301"


def test_ffhse_profiles_differ(mock_server):
    m = mock_server("ffhse_mock_server.py", 1089, "--profile", "flow")
    a, _ = nmap_scan(1089, SCRIPT)
    m.stop()
    mock_server("ffhse_mock_server.py", 1089, "--profile", "pressure")
    b, _ = nmap_scan(1089, SCRIPT)
    assert a.get("vendor") != b.get("vendor"), (a, b)
