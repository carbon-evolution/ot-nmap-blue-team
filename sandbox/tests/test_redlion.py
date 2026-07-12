import os

import pytest

from conftest import LESSER, nmap_scan

SCRIPT = os.path.join(LESSER, "redlion-cr3-info-improved.nse")

pytestmark = pytest.mark.privileged

not_root = os.geteuid() != 0
skip_reason = "needs root to bind privileged TCP 789"


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_redlion_extracts_model(mock_server):
    mock_server("redlion_mock_server.py", 789, "--model", "G310C2")
    fields, out = nmap_scan(789, SCRIPT)
    assert "model" in fields, out
    assert fields["model"] == "G310C2"
    # NSE labels are "Firmware Version" and "Manufacturer" (parse_fields
    # lowercases them), not "firmware"/"vendor".
    assert "firmware version" in fields, out
    assert fields["firmware version"] == "Crimson 3.2"
    assert "manufacturer" in fields, out
    assert "Red Lion" in fields["manufacturer"]


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_redlion_models_differ(mock_server):
    m = mock_server("redlion_mock_server.py", 789, "--model", "G310C2")
    a, _ = nmap_scan(789, SCRIPT)
    m.stop()
    mock_server("redlion_mock_server.py", 789, "--model", "G315C2")
    b, _ = nmap_scan(789, SCRIPT)
    assert a.get("model") != b.get("model"), (a, b)
