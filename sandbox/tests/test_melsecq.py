import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "melsecq-info-improved.nse")


def test_melsecq_extracts_plc_type(mock_server):
    mock_server("melsecq_mock_server.py", 5007, "--profile", "q03udvcpu")
    fields, out = nmap_scan(5007, SCRIPT)
    assert "plc type" in fields, out
    assert fields["plc type"].startswith("Q03")


def test_melsecq_profiles_differ(mock_server):
    m = mock_server("melsecq_mock_server.py", 5007, "--profile", "q03udvcpu")
    a, _ = nmap_scan(5007, SCRIPT)
    m.stop()
    mock_server("melsecq_mock_server.py", 5007, "--profile", "q26udvcpu")
    b, _ = nmap_scan(5007, SCRIPT)
    assert a.get("plc type") != b.get("plc type"), (a, b)
