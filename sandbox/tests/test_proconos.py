import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "proconos-info-improved.nse")


def test_proconos_extracts_runtime(mock_server):
    mock_server("proconos_mock_server.py", 20547, "--profile", "adam5510kw")
    fields, out = nmap_scan(20547, SCRIPT)
    assert "runtime" in fields, out


def test_proconos_profiles_differ(mock_server):
    m = mock_server("proconos_mock_server.py", 20547, "--profile", "adam5510kw")
    a, _ = nmap_scan(20547, SCRIPT)
    m.stop()
    mock_server("proconos_mock_server.py", 20547, "--profile", "adam5510e")
    b, _ = nmap_scan(20547, SCRIPT)
    assert a.get("plc model") != b.get("plc model"), (a, b)
