import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "opcua-discovery-improved.nse")


def test_opcua_extracts_application_fields(mock_server):
    mock_server("opcua_mock_server.py", 4840, "--profile", "siemens_s7")
    fields, out = nmap_scan(4840, SCRIPT)
    assert "application name" in fields, out
    assert "application uri" in fields, out


def test_opcua_profiles_differ(mock_server):
    m = mock_server("opcua_mock_server.py", 4840, "--profile", "siemens_s7")
    a, _ = nmap_scan(4840, SCRIPT)
    m.stop()
    mock_server("opcua_mock_server.py", 4840, "--profile", "rockwell_logix")
    b, _ = nmap_scan(4840, SCRIPT)
    assert a.get("application uri") != b.get("application uri"), (a, b)
