import os
from conftest import SCRIPTS, nmap_scan

SCRIPT = os.path.join(SCRIPTS, "enip-identity-improved.nse")


def test_enip_extracts_identity(mock_server):
    mock_server("enip_mock_server.py", 44818, "--profile", "controllogix")
    fields, out = nmap_scan(44818, SCRIPT)
    assert "product name" in fields, out
    assert "1756-L61" in fields["product name"], out
    assert "serial number" in fields, out
    assert "vendor" in fields, out
    assert "Allen-Bradley" in fields["vendor"], out


def test_enip_profiles_differ(mock_server):
    m = mock_server("enip_mock_server.py", 44818, "--profile", "controllogix")
    a, _ = nmap_scan(44818, SCRIPT)
    m.stop()
    mock_server("enip_mock_server.py", 44818, "--profile", "omron_nx")
    b, _ = nmap_scan(44818, SCRIPT)
    assert a.get("product name") != b.get("product name"), (a, b)
