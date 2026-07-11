import os
from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "gesrtp-info-improved.nse")


def test_gesrtp_extracts_plc_fields(mock_server):
    mock_server("gesrtp_mock_server.py", 18245, "--profile", "rx3i")
    fields, out = nmap_scan(18245, SCRIPT)
    assert "plc model" in fields, out
    assert "GE PACSystems RX3i" in fields["plc model"]
    assert "firmware version" in fields, out
    assert fields["firmware version"] == "V9.50"


def test_gesrtp_profiles_differ(mock_server):
    # The GE SRTP portrule is pinned to 18245, so profiles can't run
    # simultaneously on different ports. Start profile A, scan, stop it,
    # then start profile B on the same port and scan again.
    m1 = mock_server("gesrtp_mock_server.py", 18245, "--profile", "rx3i")
    a, _ = nmap_scan(18245, SCRIPT)
    m1.stop()
    mock_server("gesrtp_mock_server.py", 18245, "--profile", "ge90_30")
    b, _ = nmap_scan(18245, SCRIPT)
    assert a.get("cpu type") != b.get("cpu type"), (a, b)
